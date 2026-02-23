package app

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"

	"github.com/saba-futai/sudoku/internal/config"
	"github.com/saba-futai/sudoku/internal/tunnel"
	"github.com/saba-futai/sudoku/pkg/connutil"
	"github.com/saba-futai/sudoku/pkg/crypto"
	"github.com/saba-futai/sudoku/pkg/geodata"
	"github.com/saba-futai/sudoku/pkg/logx"
	"github.com/saba-futai/sudoku/pkg/obfs/sudoku"
)

type PeekConn struct {
	net.Conn
	peeked []byte
}

func (c *PeekConn) CloseWrite() error {
	if c == nil {
		return nil
	}
	return connutil.TryCloseWrite(c.Conn)
}

func (c *PeekConn) CloseRead() error {
	if c == nil {
		return nil
	}
	return connutil.TryCloseRead(c.Conn)
}

func (c *PeekConn) Read(p []byte) (n int, err error) {
	if len(c.peeked) > 0 {
		n = copy(p, c.peeked)
		c.peeked = c.peeked[n:]
		return n, nil
	}
	if c.Conn == nil {
		return 0, io.EOF
	}
	return c.Conn.Read(p)
}

func normalizeClientKey(cfg *config.Config) ([]byte, bool, error) {
	pubKeyPoint, err := crypto.RecoverPublicKey(cfg.Key)
	if err != nil {
		return nil, false, nil
	}

	privateKeyBytes, err := hex.DecodeString(cfg.Key)
	if err != nil {
		return nil, false, fmt.Errorf("decode key: %w", err)
	}

	cfg.Key = crypto.EncodePoint(pubKeyPoint)
	return privateKeyBytes, true, nil
}

func RunClient(cfg *config.Config, tables []*sudoku.Table) {
	logx.InstallStd()
	var dialer tunnel.Dialer

	privateKeyBytes, changed, err := normalizeClientKey(cfg)
	if err != nil {
		logx.Fatalf("Client", "Failed to process key: %v", err)
	}
	if changed {
		logx.Infof("Init", "Derived Public Key: %s", cfg.Key)
	}

	if tables == nil || len(tables) == 0 || changed {
		var err error
		tables, err = BuildTables(cfg)
		if err != nil {
			logx.Fatalf("Init", "Failed to build table(s): %v", err)
		}
	}

	baseDialer := tunnel.BaseDialer{
		Config:     cfg,
		Tables:     tables,
		PrivateKey: privateKeyBytes,
	}

	if cfg.HTTPMaskSessionMuxEnabled() {
		dialer = &tunnel.MuxDialer{BaseDialer: baseDialer}
		logx.Infof("Init", "Enabled HTTPMask session mux (single tunnel, multi-target)")
	} else {
		dialer = &tunnel.AdaptiveDialer{
			BaseDialer: baseDialer,
		}
	}

	startReverseClient(cfg, &baseDialer)

	var geoMgr *geodata.Manager
	if cfg.ProxyMode == "pac" {
		geoMgr = geodata.GetInstance(cfg.RuleURLs)
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.LocalPort))
	if err != nil {
		logx.Fatalf("Client", "%v", err)
	}
	logx.Infof("Client", "Client (Mixed) on :%d -> %s | Mode: %s | Rules: %d",
		cfg.LocalPort, cfg.ServerAddress, cfg.ProxyMode, len(cfg.RuleURLs))

	var primaryTable *sudoku.Table
	if len(tables) > 0 {
		primaryTable = tables[0]
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go handleMixedConn(c, cfg, primaryTable, geoMgr, dialer)
	}
}

func handleMixedConn(c net.Conn, cfg *config.Config, table *sudoku.Table, geoMgr *geodata.Manager, dialer tunnel.Dialer) {
	buf := make([]byte, 1)
	if _, err := io.ReadFull(c, buf); err != nil {
		c.Close()
		return
	}

	pConn := &PeekConn{Conn: c, peeked: buf}

	switch buf[0] {
	case 0x05:
		handleClientSocks5(pConn, cfg, table, geoMgr, dialer)
	case 0x04:
		handleClientSocks4(pConn, cfg, table, geoMgr, dialer)
	default:
		handleHTTP(pConn, cfg, table, geoMgr, dialer)
	}
}
