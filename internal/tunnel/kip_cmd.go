package tunnel

import (
	"bytes"
	"fmt"
	"net"

	"github.com/saba-futai/sudoku/internal/protocol"
)

func writeKIPOpenTCP(conn net.Conn, addr string) error {
	if conn == nil {
		return fmt.Errorf("nil conn")
	}
	var b bytes.Buffer
	if err := protocol.WriteAddress(&b, addr); err != nil {
		return fmt.Errorf("encode address failed: %w", err)
	}
	return WriteKIPMessage(conn, KIPTypeOpenTCP, b.Bytes())
}
