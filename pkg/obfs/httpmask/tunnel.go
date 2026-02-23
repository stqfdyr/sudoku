package httpmask

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type TunnelMode string

const (
	TunnelModeLegacy TunnelMode = "legacy"
	TunnelModeStream TunnelMode = "stream"
	TunnelModePoll   TunnelMode = "poll"
	TunnelModeAuto   TunnelMode = "auto"
)

func normalizeTunnelMode(mode string) TunnelMode {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", string(TunnelModeLegacy):
		return TunnelModeLegacy
	case string(TunnelModeStream):
		return TunnelModeStream
	case string(TunnelModePoll):
		return TunnelModePoll
	case string(TunnelModeAuto):
		return TunnelModeAuto
	default:
		// Be conservative: unknown => legacy
		return TunnelModeLegacy
	}
}

func multiplexEnabled(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto", "on":
		return true
	default:
		return false
	}
}

type HandleResult int

const (
	HandlePassThrough HandleResult = iota
	HandleStartTunnel
	HandleDone
)

type TunnelDialOptions struct {
	Mode         string
	TLSEnabled   bool   // when true, use HTTPS; when false, use HTTP (no port-based inference)
	HostOverride string // optional Host header / SNI host (without scheme); port inferred from ServerAddress
	// PathRoot is an optional first-level path prefix for all HTTP tunnel endpoints.
	// Example: "aabbcc" => "/aabbcc/session", "/aabbcc/api/v1/upload", ...
	PathRoot string
	// AuthKey enables short-term HMAC auth for HTTP tunnel requests (anti-probing).
	// When set (non-empty), each HTTP request carries an Authorization bearer token derived from AuthKey.
	AuthKey string
	// Upgrade optionally wraps the raw tunnel conn and/or writes a small prelude before DialTunnel returns.
	// It is called with the raw tunnel conn; if it returns a non-nil conn, that conn is returned by DialTunnel.
	//
	// Upgrade is primarily used to reduce RTT by sending initial bytes (e.g. protocol handshake) while the
	// HTTP tunnel is still establishing.
	Upgrade func(raw net.Conn) (net.Conn, error)
	// Multiplex controls whether DialTunnel reuses underlying HTTP connections (keep-alive / h2).
	// Values: "off" disables global reuse; "auto"/"on" enables it. Empty defaults to "auto".
	Multiplex string
}

// DialTunnel establishes a bidirectional stream over HTTP:
//   - stream: split-stream (authorize + upload/pull endpoints; CDN-friendly)
//   - poll: authorize + push/pull polling tunnel (base64 framed)
//   - auto: try stream then fall back to poll
//
// The returned net.Conn carries the raw Sudoku stream (no HTTP headers).
func DialTunnel(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	mode := normalizeTunnelMode(opts.Mode)
	if mode == TunnelModeLegacy {
		return nil, fmt.Errorf("legacy mode does not use http tunnel")
	}

	switch mode {
	case TunnelModeStream:
		return dialStreamFn(ctx, serverAddress, opts)
	case TunnelModePoll:
		return dialPollFn(ctx, serverAddress, opts)
	case TunnelModeAuto:
		// "stream" can hang on some CDNs that buffer uploads until request body completes.
		// Keep it on a short leash so we can fall back to poll within the caller's deadline.
		streamCtx, cancelStream := context.WithTimeout(ctx, 3*time.Second)
		c, errStream := dialStreamFn(streamCtx, serverAddress, opts)
		cancelStream()
		if errStream == nil {
			return c, nil
		}
		c, errPoll := dialPollFn(ctx, serverAddress, opts)
		if errPoll == nil {
			return c, nil
		}
		return nil, fmt.Errorf("auto tunnel failed: stream: %v; poll: %w", errStream, errPoll)
	default:
		return dialStreamFn(ctx, serverAddress, opts)
	}
}

var (
	dialStreamFn = dialStream
	dialPollFn   = dialPoll
)

func canonicalHeaderHost(urlHost, scheme string) string {
	host, port, err := net.SplitHostPort(urlHost)
	if err != nil {
		return urlHost
	}

	defaultPort := ""
	switch scheme {
	case "https":
		defaultPort = "443"
	case "http":
		defaultPort = "80"
	}
	if defaultPort == "" || port != defaultPort {
		return urlHost
	}

	// If we strip the port from an IPv6 literal, re-add brackets to keep the Host header valid.
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func parseTunnelToken(body []byte) (string, error) {
	s := strings.TrimSpace(string(body))
	idx := strings.Index(s, "token=")
	if idx < 0 {
		return "", errors.New("missing token")
	}
	s = s[idx+len("token="):]
	if s == "" {
		return "", errors.New("empty token")
	}
	// Token is base64.RawURLEncoding (A-Z a-z 0-9 - _). Strip any trailing bytes (e.g. from CDN compression).
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteByte(c)
			continue
		}
		break
	}
	token := b.String()
	if token == "" {
		return "", errors.New("empty token")
	}
	return token, nil
}

func dialStream(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	// "stream" mode uses split-stream to stay CDN-friendly by default.
	return dialStreamSplit(ctx, serverAddress, opts)
}

type queuedConn struct {
	rxc    chan []byte
	closed chan struct{}

	writeCh chan []byte
	// writeClosed is closed by CloseWrite to stop accepting new payloads.
	// When closed, Write returns io.ErrClosedPipe, but Read is unaffected.
	writeClosed chan struct{}

	mu         sync.Mutex
	readBuf    []byte
	closeErr   error
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *queuedConn) CloseWrite() error {
	if c == nil || c.writeClosed == nil {
		return nil
	}
	c.mu.Lock()
	if !isClosedPipeChan(c.writeClosed) {
		close(c.writeClosed)
	}
	c.mu.Unlock()
	return nil
}

func (c *queuedConn) closeWithError(err error) error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil
	default:
		if err == nil {
			err = io.ErrClosedPipe
		}
		if c.closeErr == nil {
			c.closeErr = err
		}
		close(c.closed)
	}
	c.mu.Unlock()
	return nil
}

func (c *queuedConn) closedErr() error {
	c.mu.Lock()
	err := c.closeErr
	c.mu.Unlock()
	if err == nil {
		return io.ErrClosedPipe
	}
	return err
}

func (c *queuedConn) Read(b []byte) (n int, err error) {
	if len(c.readBuf) == 0 {
		select {
		case c.readBuf = <-c.rxc:
		case <-c.closed:
			return 0, c.closedErr()
		}
	}
	n = copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *queuedConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return 0, c.closedErr()
	default:
	}
	if c.writeClosed != nil {
		select {
		case <-c.writeClosed:
			c.mu.Unlock()
			return 0, io.ErrClosedPipe
		default:
		}
	}
	c.mu.Unlock()

	payload := make([]byte, len(b))
	copy(payload, b)
	if c.writeClosed == nil {
		select {
		case c.writeCh <- payload:
			return len(b), nil
		case <-c.closed:
			return 0, c.closedErr()
		}
	}
	select {
	case c.writeCh <- payload:
		return len(b), nil
	case <-c.closed:
		return 0, c.closedErr()
	case <-c.writeClosed:
		return 0, io.ErrClosedPipe
	}
}

func (c *queuedConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *queuedConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *queuedConn) SetDeadline(time.Time) error      { return nil }
func (c *queuedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *queuedConn) SetWriteDeadline(time.Time) error { return nil }

type streamSplitConn struct {
	queuedConn

	ctx    context.Context
	cancel context.CancelFunc

	client     *http.Client
	pushURL    string
	pullURL    string
	finURL     string
	closeURL   string
	headerHost string
	auth       *tunnelAuth
}

func (c *streamSplitConn) Close() error {
	_ = c.closeWithError(io.ErrClosedPipe)

	if c.cancel != nil {
		c.cancel()
	}

	bestEffortCloseSession(c.client, c.closeURL, c.headerHost, TunnelModeStream, c.auth)

	return nil
}

type sessionDialInfo struct {
	client     *http.Client
	pushURL    string
	pullURL    string
	finURL     string
	closeURL   string
	headerHost string
	auth       *tunnelAuth
}

type transportKey struct {
	scheme     string
	urlHost    string
	dialAddr   string
	serverName string
}

var (
	transportMu   sync.Mutex
	transportPool = make(map[transportKey]*http.Transport)
)

func newHTTPClient(urlHost, dialAddr, serverName, scheme string, maxIdleConns int, reuseTransport bool) *http.Client {
	build := func() *http.Transport {
		transport := &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     scheme == "https",
			DisableCompression:    true,
			MaxIdleConns:          maxIdleConns,
			MaxIdleConnsPerHost:   maxIdleConns,
			IdleConnTimeout:       30 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				if addr == urlHost {
					addr = dialAddr
				}
				return d.DialContext(dialCtx, network, addr)
			},
		}
		if scheme == "https" {
			transport.TLSClientConfig = &tls.Config{
				ServerName: serverName,
				MinVersion: tls.VersionTLS12,
			}
		}
		return transport
	}

	if !reuseTransport {
		return &http.Client{Transport: build()}
	}

	key := transportKey{
		scheme:     scheme,
		urlHost:    urlHost,
		dialAddr:   dialAddr,
		serverName: serverName,
	}

	transportMu.Lock()
	transport := transportPool[key]
	if transport == nil {
		transport = build()
		transportPool[key] = transport
	}
	transportMu.Unlock()

	return &http.Client{Transport: transport}
}

func dialSession(ctx context.Context, serverAddress string, opts TunnelDialOptions, mode TunnelMode) (*sessionDialInfo, error) {
	scheme, urlHost, dialAddr, serverName, err := normalizeHTTPDialTarget(serverAddress, opts.TLSEnabled, opts.HostOverride)
	if err != nil {
		return nil, err
	}
	headerHost := canonicalHeaderHost(urlHost, scheme)
	auth := newTunnelAuth(opts.AuthKey, 0)

	client := newHTTPClient(urlHost, dialAddr, serverName, scheme, 32, multiplexEnabled(opts.Multiplex))

	authorizeURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: joinPathRoot(opts.PathRoot, "/session")}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizeURL, nil)
	if err != nil {
		return nil, err
	}
	req.Host = headerHost
	applyTunnelHeaders(req.Header, headerHost, mode)
	applyTunnelAuth(req, auth, mode, http.MethodGet, "/session")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s authorize bad status: %s (%s)", mode, resp.Status, strings.TrimSpace(string(bodyBytes)))
	}

	token, err := parseTunnelToken(bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("%s authorize failed: %q", mode, strings.TrimSpace(string(bodyBytes)))
	}
	if token == "" {
		return nil, fmt.Errorf("%s authorize empty token", mode)
	}

	pushURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: joinPathRoot(opts.PathRoot, "/api/v1/upload"), RawQuery: "token=" + url.QueryEscape(token)}).String()
	pullURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: joinPathRoot(opts.PathRoot, "/stream"), RawQuery: "token=" + url.QueryEscape(token)}).String()
	finURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: joinPathRoot(opts.PathRoot, "/api/v1/upload"), RawQuery: "token=" + url.QueryEscape(token) + "&fin=1"}).String()
	closeURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: joinPathRoot(opts.PathRoot, "/api/v1/upload"), RawQuery: "token=" + url.QueryEscape(token) + "&close=1"}).String()

	return &sessionDialInfo{
		client:     client,
		pushURL:    pushURL,
		pullURL:    pullURL,
		finURL:     finURL,
		closeURL:   closeURL,
		headerHost: headerHost,
		auth:       auth,
	}, nil
}

func bestEffortCloseSession(client *http.Client, closeURL, headerHost string, mode TunnelMode, auth *tunnelAuth) {
	if client == nil || closeURL == "" || headerHost == "" {
		return
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(closeCtx, http.MethodPost, closeURL, nil)
	if err != nil {
		return
	}
	req.Host = headerHost
	applyTunnelHeaders(req.Header, headerHost, mode)
	applyTunnelAuth(req, auth, mode, http.MethodPost, "/api/v1/upload")

	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
	_ = resp.Body.Close()
}

func dialStreamSplit(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	info, err := dialSession(ctx, serverAddress, opts, TunnelModeStream)
	if err != nil {
		return nil, err
	}

	connCtx, cancel := context.WithCancel(context.Background())
	c := &streamSplitConn{
		ctx:        connCtx,
		cancel:     cancel,
		client:     info.client,
		pushURL:    info.pushURL,
		pullURL:    info.pullURL,
		finURL:     info.finURL,
		closeURL:   info.closeURL,
		headerHost: info.headerHost,
		auth:       info.auth,
		queuedConn: queuedConn{
			rxc:         make(chan []byte, 256),
			closed:      make(chan struct{}),
			writeCh:     make(chan []byte, 256),
			writeClosed: make(chan struct{}),
			localAddr:   &net.TCPAddr{},
			remoteAddr:  &net.TCPAddr{},
		},
	}

	go c.pullLoop()
	go c.pushLoop()
	outConn := net.Conn(c)
	if opts.Upgrade != nil {
		upgraded, err := opts.Upgrade(c)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		if upgraded != nil {
			outConn = upgraded
		}
	}
	return outConn, nil
}

func (c *streamSplitConn) pullLoop() {
	const (
		// requestTimeout must be long enough for continuous high-throughput streams (e.g. mux + large downloads).
		// If it is too short, the client cancels the response mid-body and corrupts the byte stream.
		requestTimeout = 2 * time.Minute
		readChunkSize  = 32 * 1024
		idleBackoff    = 25 * time.Millisecond
		maxDialRetry   = 12
		minBackoff     = 10 * time.Millisecond
		maxBackoff     = 250 * time.Millisecond
	)

	var (
		dialRetry int
		backoff   = minBackoff
	)
	buf := make([]byte, readChunkSize)
	for {
		select {
		case <-c.closed:
			return
		default:
		}

		reqCtx, cancel := context.WithTimeout(c.ctx, requestTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, c.pullURL, nil)
		if err != nil {
			cancel()
			_ = c.Close()
			return
		}
		req.Host = c.headerHost
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModeStream)
		applyTunnelAuth(req, c.auth, TunnelModeStream, http.MethodGet, "/stream")

		resp, err := c.client.Do(req)
		if err != nil {
			cancel()
			if isDialError(err) && dialRetry < maxDialRetry {
				dialRetry++
				select {
				case <-time.After(backoff):
				case <-c.closed:
					return
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			_ = c.Close()
			return
		}
		dialRetry = 0
		backoff = minBackoff

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			cancel()
			_ = c.Close()
			return
		}

		readAny := false
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				readAny = true
				payload := make([]byte, n)
				copy(payload, buf[:n])
				select {
				case c.rxc <- payload:
				case <-c.closed:
					_ = resp.Body.Close()
					cancel()
					return
				}
			}
			if rerr != nil {
				_ = resp.Body.Close()
				cancel()
				if errors.Is(rerr, io.EOF) {
					// Long-poll ended; retry.
					break
				}
				_ = c.Close()
				return
			}
		}
		cancel()
		if !readAny {
			// Avoid tight loop if the server replied quickly with an empty body.
			select {
			case <-time.After(idleBackoff):
			case <-c.closed:
				return
			}
		}
	}
}

func (c *streamSplitConn) pushLoop() {
	const (
		maxBatchBytes  = 256 * 1024
		flushInterval  = 5 * time.Millisecond
		requestTimeout = 20 * time.Second
		maxDialRetry   = 12
		minBackoff     = 10 * time.Millisecond
		maxBackoff     = 250 * time.Millisecond
	)

	var (
		buf   bytes.Buffer
		timer = time.NewTimer(flushInterval)
	)
	defer timer.Stop()

	flush := func() error {
		if buf.Len() == 0 {
			return nil
		}

		reqCtx, cancel := context.WithTimeout(c.ctx, requestTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.pushURL, bytes.NewReader(buf.Bytes()))
		if err != nil {
			cancel()
			return err
		}
		req.Host = c.headerHost
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModeStream)
		applyTunnelAuth(req, c.auth, TunnelModeStream, http.MethodPost, "/api/v1/upload")
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := c.client.Do(req)
		if err != nil {
			cancel()
			return err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("bad status: %s", resp.Status)
		}

		buf.Reset()
		return nil
	}

	flushWithRetry := func() error {
		return retryDial(c.closed, func() error { return io.ErrClosedPipe }, maxDialRetry, minBackoff, maxBackoff, flush)
	}
	resetTimer(timer, flushInterval)

	for {
		select {
		case b, ok := <-c.writeCh:
			if !ok {
				_ = flushWithRetry()
				return
			}
			if len(b) == 0 {
				continue
			}
			if buf.Len()+len(b) > maxBatchBytes {
				if err := flushWithRetry(); err != nil {
					_ = c.Close()
					return
				}
				resetTimer(timer, flushInterval)
			}
			_, _ = buf.Write(b)
			if buf.Len() >= maxBatchBytes {
				if err := flushWithRetry(); err != nil {
					_ = c.Close()
					return
				}
				resetTimer(timer, flushInterval)
			}
		case <-timer.C:
			if err := flushWithRetry(); err != nil {
				_ = c.Close()
				return
			}
			resetTimer(timer, flushInterval)
		case <-c.writeClosed:
			// Drain any already-accepted writes so CloseWrite does not lose data.
			for {
				select {
				case b := <-c.writeCh:
					if len(b) == 0 {
						continue
					}
					if buf.Len()+len(b) > maxBatchBytes {
						if err := flushWithRetry(); err != nil {
							_ = c.Close()
							return
						}
					}
					_, _ = buf.Write(b)
				default:
					_ = flushWithRetry()
					bestEffortCloseSession(c.client, c.finURL, c.headerHost, TunnelModeStream, c.auth)
					return
				}
			}
		case <-c.closed:
			_ = flushWithRetry()
			return
		}
	}
}

type pollConn struct {
	queuedConn

	ctx    context.Context
	cancel context.CancelFunc

	client     *http.Client
	pushURL    string
	pullURL    string
	finURL     string
	closeURL   string
	headerHost string
	auth       *tunnelAuth
}

func isDialError(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return isDialError(urlErr.Err)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" || opErr.Op == "connect" {
			return true
		}
	}
	return false
}

func resetTimer(t *time.Timer, d time.Duration) {
	if t == nil {
		return
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

func retryDial(closed <-chan struct{}, closedErr func() error, maxRetry int, minBackoff, maxBackoff time.Duration, fn func() error) error {
	backoff := minBackoff
	for tries := 0; ; tries++ {
		if err := fn(); err == nil {
			return nil
		} else if isDialError(err) && tries < maxRetry {
			select {
			case <-time.After(backoff):
			case <-closed:
				if closedErr != nil {
					return closedErr()
				}
				return io.ErrClosedPipe
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		} else {
			return err
		}
	}
}

func (c *pollConn) closeWithError(err error) error {
	_ = c.queuedConn.closeWithError(err)
	if c.cancel != nil {
		c.cancel()
	}
	bestEffortCloseSession(c.client, c.closeURL, c.headerHost, TunnelModePoll, c.auth)
	return nil
}

func (c *pollConn) Close() error {
	return c.closeWithError(io.ErrClosedPipe)
}

func dialPoll(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	info, err := dialSession(ctx, serverAddress, opts, TunnelModePoll)
	if err != nil {
		return nil, err
	}

	connCtx, cancel := context.WithCancel(context.Background())
	c := &pollConn{
		ctx:        connCtx,
		cancel:     cancel,
		client:     info.client,
		pushURL:    info.pushURL,
		pullURL:    info.pullURL,
		finURL:     info.finURL,
		closeURL:   info.closeURL,
		headerHost: info.headerHost,
		auth:       info.auth,
		queuedConn: queuedConn{
			rxc:         make(chan []byte, 128),
			closed:      make(chan struct{}),
			writeCh:     make(chan []byte, 256),
			writeClosed: make(chan struct{}),
			localAddr:   &net.TCPAddr{},
			remoteAddr:  &net.TCPAddr{},
		},
	}

	go c.pullLoop()
	go c.pushLoop()
	outConn := net.Conn(c)
	if opts.Upgrade != nil {
		upgraded, err := opts.Upgrade(c)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		if upgraded != nil {
			outConn = upgraded
		}
	}
	return outConn, nil
}

func (c *pollConn) pullLoop() {
	const (
		maxDialRetry = 12
		minBackoff   = 10 * time.Millisecond
		maxBackoff   = 250 * time.Millisecond
	)

	var (
		dialRetry int
		backoff   = minBackoff
	)
	for {
		select {
		case <-c.closed:
			return
		default:
		}

		req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.pullURL, nil)
		if err != nil {
			_ = c.closeWithError(err)
			return
		}
		req.Host = c.headerHost
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModePoll)
		applyTunnelAuth(req, c.auth, TunnelModePoll, http.MethodGet, "/stream")

		resp, err := c.client.Do(req)
		if err != nil {
			if isDialError(err) && dialRetry < maxDialRetry {
				dialRetry++
				select {
				case <-time.After(backoff):
				case <-c.closed:
					return
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			_ = c.closeWithError(fmt.Errorf("poll pull request failed: %w", err))
			return
		}
		dialRetry = 0
		backoff = minBackoff

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			_ = c.closeWithError(fmt.Errorf("poll pull bad status: %s", resp.Status))
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			payload, err := base64.StdEncoding.DecodeString(line)
			if err != nil {
				_ = resp.Body.Close()
				_ = c.closeWithError(fmt.Errorf("poll pull decode failed: %w", err))
				return
			}
			select {
			case c.rxc <- payload:
			case <-c.closed:
				_ = resp.Body.Close()
				return
			}
		}
		_ = resp.Body.Close()
		if err := scanner.Err(); err != nil {
			_ = c.closeWithError(fmt.Errorf("poll pull scan failed: %w", err))
			return
		}
	}
}

func (c *pollConn) pushLoop() {
	const (
		maxBatchBytes   = 64 * 1024
		flushInterval   = 5 * time.Millisecond
		maxLineRawBytes = 16 * 1024
		maxDialRetry    = 12
		minBackoff      = 10 * time.Millisecond
		maxBackoff      = 250 * time.Millisecond
	)

	var (
		buf        bytes.Buffer
		pendingRaw int
		timer      = time.NewTimer(flushInterval)
	)
	defer timer.Stop()

	flush := func() error {
		if buf.Len() == 0 {
			return nil
		}

		reqCtx, cancel := context.WithTimeout(c.ctx, 20*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.pushURL, bytes.NewReader(buf.Bytes()))
		if err != nil {
			cancel()
			return err
		}
		req.Host = c.headerHost
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModePoll)
		applyTunnelAuth(req, c.auth, TunnelModePoll, http.MethodPost, "/api/v1/upload")
		req.Header.Set("Content-Type", "text/plain")

		resp, err := c.client.Do(req)
		if err != nil {
			cancel()
			return err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("bad status: %s", resp.Status)
		}

		buf.Reset()
		pendingRaw = 0
		return nil
	}

	flushWithRetry := func() error {
		return retryDial(c.closed, c.closedErr, maxDialRetry, minBackoff, maxBackoff, flush)
	}
	resetTimer(timer, flushInterval)

	enqueue := func(b []byte) error {
		for len(b) > 0 {
			chunk := b
			if len(chunk) > maxLineRawBytes {
				chunk = b[:maxLineRawBytes]
			}
			b = b[len(chunk):]

			encLen := base64.StdEncoding.EncodedLen(len(chunk))
			if pendingRaw+len(chunk) > maxBatchBytes || buf.Len()+encLen+1 > maxBatchBytes*2 {
				if err := flushWithRetry(); err != nil {
					return err
				}
			}

			tmp := make([]byte, encLen)
			base64.StdEncoding.Encode(tmp, chunk)
			buf.Write(tmp)
			buf.WriteByte('\n')
			pendingRaw += len(chunk)
		}
		return nil
	}

	for {
		select {
		case b, ok := <-c.writeCh:
			if !ok {
				_ = flushWithRetry()
				return
			}
			if len(b) == 0 {
				continue
			}

			if err := enqueue(b); err != nil {
				_ = c.closeWithError(fmt.Errorf("poll push flush failed: %w", err))
				return
			}

			if pendingRaw >= maxBatchBytes {
				if err := flushWithRetry(); err != nil {
					_ = c.closeWithError(fmt.Errorf("poll push flush failed: %w", err))
					return
				}
				resetTimer(timer, flushInterval)
			}
		case <-timer.C:
			if err := flushWithRetry(); err != nil {
				_ = c.closeWithError(fmt.Errorf("poll push flush failed: %w", err))
				return
			}
			resetTimer(timer, flushInterval)
		case <-c.writeClosed:
			// Drain any already-accepted writes so CloseWrite does not lose data.
			for {
				select {
				case b := <-c.writeCh:
					if len(b) == 0 {
						continue
					}
					if err := enqueue(b); err != nil {
						_ = c.closeWithError(fmt.Errorf("poll push flush failed: %w", err))
						return
					}
				default:
					_ = flushWithRetry()
					bestEffortCloseSession(c.client, c.finURL, c.headerHost, TunnelModePoll, c.auth)
					return
				}
			}
		case <-c.closed:
			_ = flushWithRetry()
			return
		}
	}
}

func normalizeHTTPDialTarget(serverAddress string, tlsEnabled bool, hostOverride string) (scheme, urlHost, dialAddr, serverName string, err error) {
	host, port, err := net.SplitHostPort(serverAddress)
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid server address %q: %w", serverAddress, err)
	}

	if hostOverride != "" {
		// Allow "example.com" or "example.com:443"
		if h, p, splitErr := net.SplitHostPort(hostOverride); splitErr == nil {
			if h != "" {
				hostOverride = h
			}
			if p != "" {
				port = p
			}
		}
		serverName = hostOverride
		urlHost = net.JoinHostPort(hostOverride, port)
	} else {
		serverName = host
		urlHost = net.JoinHostPort(host, port)
	}

	if tlsEnabled {
		scheme = "https"
	} else {
		scheme = "http"
	}

	dialAddr = net.JoinHostPort(host, port)
	return scheme, urlHost, dialAddr, trimPortForHost(serverName), nil
}

func applyTunnelHeaders(h http.Header, host string, mode TunnelMode) {
	r := rngPool.Get().(*mrand.Rand)
	ua := userAgents[r.Intn(len(userAgents))]
	accept := accepts[r.Intn(len(accepts))]
	lang := acceptLanguages[r.Intn(len(acceptLanguages))]
	rngPool.Put(r)

	h.Set("User-Agent", ua)
	h.Set("Accept", accept)
	h.Set("Accept-Language", lang)
	h.Set("Cache-Control", "no-cache")
	h.Set("Pragma", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("Host", host)
	h.Set("X-Sudoku-Tunnel", string(mode))
	h.Set("X-Sudoku-Version", "1")
}
