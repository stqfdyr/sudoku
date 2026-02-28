package apis

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/saba-futai/sudoku/internal/tunnel"
)

// DialUDPOverTCP bootstraps a UDP-over-TCP tunnel using the standard Dial flow.
func DialUDPOverTCP(ctx context.Context, cfg *ProtocolConfig) (net.Conn, error) {
	conn, err := establishBaseConn(ctx, cfg, validateBaseClientConfig, nil)
	if err != nil {
		return nil, err
	}
	if err := tunnel.WriteKIPMessage(conn, tunnel.KIPTypeStartUoT, nil); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write uot preface: %w", err)
	}
	return conn, nil
}

// HandleUoT runs the UDP-over-TCP loop on an upgraded tunnel connection.
func HandleUoT(conn net.Conn) error {
	return tunnel.HandleUoTServer(conn)
}

func WriteUoTDatagram(w io.Writer, addr string, payload []byte) error {
	return tunnel.WriteUoTDatagram(w, addr, payload)
}

func ReadUoTDatagram(r io.Reader) (string, []byte, error) {
	return tunnel.ReadUoTDatagram(r)
}
