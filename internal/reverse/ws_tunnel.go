package reverse

import (
	"net/http"
	"strings"

	"github.com/coder/websocket"
	"github.com/saba-futai/sudoku/internal/tunnel"
)

const sudokuTCPSubprotocol = "sudoku-tcp-v1"

func serveSudokuTCPTunnel(w http.ResponseWriter, r *http.Request, mux *tunnel.MuxClient, target string) {
	if w == nil || r == nil || mux == nil || strings.TrimSpace(target) == "" {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:    []string{sudokuTCPSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		// Accept already wrote the response.
		return
	}
	if c.Subprotocol() != sudokuTCPSubprotocol {
		_ = c.Close(websocket.StatusPolicyViolation, "subprotocol required")
		return
	}

	up, err := mux.Dial(target)
	if err != nil {
		_ = c.Close(websocket.StatusInternalError, "dial failed")
		return
	}

	wsConn := websocket.NetConn(r.Context(), c, websocket.MessageBinary)
	tunnel.PipeConn(wsConn, up)
}

func websocketClientOffersSubprotocol(r *http.Request, want string) bool {
	if r == nil {
		return false
	}
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, part := range strings.Split(v, ",") {
			if strings.TrimSpace(part) == want {
				return true
			}
		}
	}
	return false
}

func isWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return false
	}
	return headerHasToken(r.Header, "Connection", "upgrade")
}

func headerHasToken(h http.Header, key, token string) bool {
	if h == nil {
		return false
	}
	token = strings.ToLower(strings.TrimSpace(token))
	if token == "" {
		return false
	}
	for _, v := range h.Values(key) {
		for _, part := range strings.Split(v, ",") {
			if strings.ToLower(strings.TrimSpace(part)) == token {
				return true
			}
		}
	}
	return false
}
