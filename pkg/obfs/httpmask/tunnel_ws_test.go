package httpmask

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestWebSocketTunnel_Echo(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := NewTunnelServer(TunnelServerOptions{
		Mode:     "ws",
		PathRoot: "root",
		AuthKey:  "k",
	})

	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer raw.Close()

		res, c, err := srv.HandleConn(raw)
		if err != nil {
			errCh <- err
			return
		}
		if res != HandleStartTunnel || c == nil {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		defer c.Close()

		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err != nil {
			errCh <- err
			return
		}
		if _, err := c.Write(buf); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := DialTunnel(ctx, ln.Addr().String(), TunnelDialOptions{
		Mode:       "ws",
		TLSEnabled: false,
		PathRoot:   "root",
		AuthKey:    "k",
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	msg := []byte("hello")
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", string(buf), string(msg))
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("server timeout")
	}
}
