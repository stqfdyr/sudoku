package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/saba-futai/sudoku/internal/app"
	"github.com/saba-futai/sudoku/internal/config"
	"github.com/saba-futai/sudoku/pkg/crypto"
	"github.com/saba-futai/sudoku/pkg/obfs/sudoku"
)

const (
	demoAEAD        = "chacha20-poly1305"
	demoASCII       = "prefer_ascii"
	demoCustomTable = "xpxvvpvv"
)

func main() {
	prefixFlag := flag.String("prefix", "/demo", "Reverse proxy prefix (e.g. /demo)")
	noCheck := flag.Bool("no-check", false, "Skip automated checks (leave servers running)")
	once := flag.Bool("once", false, "Exit after checks (useful for CI/local sanity runs)")
	flag.Parse()

	prefix := normalizePrefix(*prefixFlag)
	if prefix == "" {
		log.Fatalf("invalid prefix: %q", *prefixFlag)
	}

	backendAddr, backendClose, err := startBackend()
	if err != nil {
		log.Fatalf("start backend: %v", err)
	}
	defer backendClose()

	frontendAddr, frontendClose, err := startFrontend(backendAddr)
	if err != nil {
		log.Fatalf("start frontend: %v", err)
	}
	defer frontendClose()

	serverKey, clientKey, err := newKeys()
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}

	ports, err := getFreePorts(3)
	if err != nil {
		log.Fatalf("alloc ports: %v", err)
	}
	serverPort := ports[0]
	clientPort := ports[1]
	reversePort := ports[2]
	reverseListen := fmt.Sprintf("127.0.0.1:%d", reversePort)

	serverCfg := &config.Config{
		Mode:               "server",
		Transport:          "tcp",
		LocalPort:          serverPort,
		FallbackAddr:       "",
		Key:                serverKey,
		AEAD:               demoAEAD,
		SuspiciousAction:   "fallback",
		PaddingMin:         0,
		PaddingMax:         0,
		ASCII:              demoASCII,
		CustomTable:        demoCustomTable,
		EnablePureDownlink: true,
		HTTPMask:           config.HTTPMaskConfig{Disable: true},
		Reverse:            &config.ReverseConfig{Listen: reverseListen},
	}

	clientCfg := &config.Config{
		Mode:               "client",
		Transport:          "tcp",
		LocalPort:          clientPort,
		ServerAddress:      fmt.Sprintf("127.0.0.1:%d", serverPort),
		Key:                clientKey,
		AEAD:               demoAEAD,
		PaddingMin:         0,
		PaddingMax:         0,
		ASCII:              demoASCII,
		CustomTable:        demoCustomTable,
		EnablePureDownlink: true,
		ProxyMode:          "direct",
		HTTPMask:           config.HTTPMaskConfig{Disable: true},
		Reverse: &config.ReverseConfig{
			ClientID: "demo",
			Routes: []config.ReverseRoute{
				{Path: prefix, Target: frontendAddr},
			},
		},
	}

	serverTable, err := sudoku.NewTableWithCustom(serverCfg.Key, serverCfg.ASCII, serverCfg.CustomTable)
	if err != nil {
		log.Fatalf("build server table: %v", err)
	}
	clientTable, err := sudoku.NewTableWithCustom(clientCfg.Key, clientCfg.ASCII, clientCfg.CustomTable)
	if err != nil {
		log.Fatalf("build client table: %v", err)
	}

	go app.RunServer(serverCfg, []*sudoku.Table{serverTable})
	mustWaitForTCP(serverCfg.LocalPort)
	mustWaitForTCPAddr(reverseListen)

	go app.RunClient(clientCfg, []*sudoku.Table{clientTable})
	mustWaitForTCP(clientCfg.LocalPort)

	if err := waitForReverseRouteReady(reverseListen, prefix); err != nil {
		log.Fatalf("reverse route not ready: %v", err)
	}

	log.Printf("Backend (API+WS):  http://%s", backendAddr)
	log.Printf("Frontend (static): http://%s", frontendAddr)
	log.Printf("Reverse entry:     http://%s%s/", reverseListen, prefix)

	if !*noCheck {
		if err := runChecks(reverseListen, prefix); err != nil {
			log.Fatalf("e2e checks failed: %v", err)
		}
		log.Printf("E2E checks OK")
	}

	if *once {
		return
	}

	log.Printf("Press Ctrl+C to stop")
	waitForSignal()
}

func normalizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return strings.TrimRight(prefix, "/")
}

func newKeys() (serverKey, clientKey string, err error) {
	pair, err := crypto.GenerateMasterKey()
	if err != nil {
		return "", "", err
	}
	return crypto.EncodePoint(pair.Public), crypto.EncodeScalar(pair.Private), nil
}

func startBackend() (addr string, closeFn func(), err error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("pong"))
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		defer c.Close(websocket.StatusNormalClosure, "")

		ctx := r.Context()
		for {
			typ, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			if err := c.Write(ctx, typ, data); err != nil {
				return
			}
		}
	})
	return startHTTPServer("backend", mux)
}

func startFrontend(backendAddr string) (addr string, closeFn func(), err error) {
	u, err := url.Parse("http://" + backendAddr)
	if err != nil {
		return "", nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[frontend] proxy error: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", rp)
	mux.Handle("/ws", rp)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(demoIndexHTML))
	})
	mux.HandleFunc("/static/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write([]byte(demoCSS))
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write([]byte(demoJS))
	})
	mux.HandleFunc("/static/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write([]byte(demoLogoSVG))
	})
	mux.HandleFunc("/static/bg.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write([]byte(demoBgSVG))
	})

	return startHTTPServer("frontend", mux)
}

func startHTTPServer(name string, handler http.Handler) (addr string, closeFn func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[%s] serve error: %v", name, err)
		}
	}()
	return ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
		_ = ln.Close()
	}, nil
}

func mustWaitForTCP(port int) {
	if port <= 0 {
		return
	}
	mustWaitForTCPAddr(fmt.Sprintf("127.0.0.1:%d", port))
}

func mustWaitForTCPAddr(addr string) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	log.Fatalf("address not ready: %s", addr)
}

func waitForReverseRouteReady(reverseListen, prefix string) error {
	if reverseListen == "" || prefix == "" || prefix == "/" {
		return fmt.Errorf("invalid reverse listen/prefix")
	}

	noFollowClient := &http.Client{
		Timeout: 500 * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := noFollowClient.Get("http://" + reverseListen + prefix)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusPermanentRedirect && strings.HasSuffix(resp.Header.Get("Location"), prefix+"/") {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout")
}

func runChecks(reverseListen, prefix string) error {
	jar, _ := cookiejar.New(nil)
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Jar:     jar,
	}

	baseURL := "http://" + reverseListen

	// 1) Load the app under subpath.
	appURL := baseURL + prefix + "/"
	resp, err := httpClient.Get(appURL)
	if err != nil {
		return fmt.Errorf("GET %s: %w", appURL, err)
	}
	htmlBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status=%d", appURL, resp.StatusCode)
	}
	html := string(htmlBytes)
	if !strings.Contains(html, `href="`+prefix+`/static/style.css"`) {
		return fmt.Errorf("index.html not rewritten for css href")
	}
	if !strings.Contains(html, `src="`+prefix+`/static/app.js"`) {
		return fmt.Errorf("index.html not rewritten for js src")
	}

	// 2) JS is served under the subpath.
	jsURL := baseURL + prefix + "/static/app.js"
	resp, err = httpClient.Get(jsURL)
	if err != nil {
		return fmt.Errorf("GET %s: %w", jsURL, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status=%d", jsURL, resp.StatusCode)
	}

	// 3) Root-path API request without Referer (cookie fallback).
	apiURL := baseURL + "/api/ping"
	resp, err = httpClient.Get(apiURL)
	if err != nil {
		return fmt.Errorf("GET %s: %w", apiURL, err)
	}
	apiBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(apiBody)) != "pong" {
		return fmt.Errorf("GET %s: status=%d body=%q", apiURL, resp.StatusCode, string(apiBody))
	}

	// 4) Root-path static request without prefix (cookie fallback).
	staticURL := baseURL + "/static/logo.svg"
	resp, err = httpClient.Get(staticURL)
	if err != nil {
		return fmt.Errorf("GET %s: %w", staticURL, err)
	}
	staticBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(staticBody), "<svg") {
		return fmt.Errorf("GET %s: status=%d", staticURL, resp.StatusCode)
	}

	// 5) WebSocket without prefix (cookie fallback).
	wsURL := "ws://" + reverseListen + "/ws"
	wsHeader := http.Header{}
	if u, err := url.Parse(baseURL); err == nil {
		if cookies := jar.Cookies(u); len(cookies) > 0 {
			wsHeader.Set("Cookie", cookieHeaderValue(cookies))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader:      wsHeader,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return fmt.Errorf("dial ws: %w", err)
	}
	defer ws.Close(websocket.StatusNormalClosure, "")

	if err := ws.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		return fmt.Errorf("ws write: %w", err)
	}
	typ, msg, err := ws.Read(ctx)
	if err != nil {
		return fmt.Errorf("ws read: %w", err)
	}
	if typ != websocket.MessageText || string(msg) != "hello" {
		return fmt.Errorf("ws echo mismatch: type=%v msg=%q", typ, string(msg))
	}
	return nil
}

func cookieHeaderValue(cookies []*http.Cookie) string {
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

func waitForSignal() {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}

func getFreePorts(count int) ([]int, error) {
	var listeners []net.Listener
	var ports []int
	for i := 0; i < count; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return nil, err
		}
		listeners = append(listeners, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	for _, l := range listeners {
		_ = l.Close()
	}
	return ports, nil
}

const demoIndexHTML = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Sudoku Reverse Proxy Demo</title>
    <link rel="stylesheet" href="/static/style.css" />
  </head>
  <body>
    <h1>Sudoku Reverse Proxy Demo</h1>
    <p id="ping">ping: pending...</p>
    <p id="ws">ws: pending...</p>
    <img alt="logo" src="/static/logo.svg" srcset="/static/logo.svg 1x, /static/logo.svg 2x" />
    <script src="/static/app.js"></script>
  </body>
</html>
`

const demoCSS = `body { font-family: sans-serif; background-image: url(/static/bg.svg); background-repeat: no-repeat; background-position: right 16px top 16px; }
img { width: 96px; height: 96px; }
`

const demoJS = `(async () => {
  const pingEl = document.getElementById("ping");
  try {
    const r = await fetch("/api/ping");
    pingEl.textContent = "ping: " + (await r.text());
  } catch (e) {
    pingEl.textContent = "ping: ERR " + e;
  }

  const wsEl = document.getElementById("ws");
  try {
    const proto = location.protocol === "https:" ? "wss://" : "ws://";
    const ws = new WebSocket(proto + location.host + "/ws");
    ws.onopen = () => { wsEl.textContent = "ws: open"; ws.send("hello"); };
    ws.onmessage = (ev) => { wsEl.textContent = "ws: " + ev.data; };
    ws.onerror = () => { wsEl.textContent = "ws: error"; };
  } catch (e) {
    wsEl.textContent = "ws: ERR " + e;
  }
})();
`

const demoLogoSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96">
  <rect x="0" y="0" width="96" height="96" rx="14" fill="#2563eb"/>
  <text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" font-family="sans-serif" font-size="32" fill="white">S</text>
</svg>
`

const demoBgSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="240" height="240" viewBox="0 0 240 240">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#93c5fd" stop-opacity="0.55"/>
      <stop offset="1" stop-color="#60a5fa" stop-opacity="0.25"/>
    </linearGradient>
  </defs>
  <circle cx="120" cy="120" r="100" fill="url(#g)"/>
</svg>
`
