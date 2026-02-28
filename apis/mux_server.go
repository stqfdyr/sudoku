package apis

import (
	"net"

	"github.com/saba-futai/sudoku/internal/tunnel"
)

// HandleMuxServer runs a "single tunnel, multi-target" mux session on an upgraded tunnel connection.
func HandleMuxServer(conn net.Conn, onConnect func(targetAddr string)) error {
	return tunnel.HandleMuxServer(conn, onConnect)
}

// HandleMuxWithDialer is like HandleMuxServer but allows the caller to control how targets are dialed.
func HandleMuxWithDialer(conn net.Conn, onConnect func(targetAddr string), dialTarget func(targetAddr string) (net.Conn, error)) error {
	return tunnel.HandleMuxWithDialer(conn, onConnect, dialTarget)
}
