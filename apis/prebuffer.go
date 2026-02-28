package apis

import (
	"net"

	"github.com/saba-futai/sudoku/internal/tunnel"
)

// NewPreBufferedConn returns a net.Conn that replays preRead before reading from conn.
//
// This is useful when you need to peek some bytes (e.g. to detect an HTTP tunnel header or probe tables)
// and still keep the stream consumable by the next parser.
func NewPreBufferedConn(conn net.Conn, preRead []byte) net.Conn {
	return tunnel.NewPreBufferedConn(conn, preRead)
}
