package app

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/saba-futai/sudoku/internal/config"
	"github.com/saba-futai/sudoku/internal/handler"
	"github.com/saba-futai/sudoku/internal/protocol"
	"github.com/saba-futai/sudoku/internal/reverse"
	"github.com/saba-futai/sudoku/internal/tunnel"
	"github.com/saba-futai/sudoku/pkg/logx"
	"github.com/saba-futai/sudoku/pkg/obfs/httpmask"
	"github.com/saba-futai/sudoku/pkg/obfs/sudoku"
)

// logUserInfo logs an info message, prepending [User:hash] when userHash is non-empty.
func logUserInfo(tag, userHash, format string, args ...interface{}) {
	if userHash != "" {
		format = "[User:" + userHash + "] " + format
	}
	logx.Infof(tag, format, args...)
}

// logUserWarn logs a warning message, prepending [User:hash] when userHash is non-empty.
func logUserWarn(tag, userHash, format string, args ...interface{}) {
	if userHash != "" {
		format = "[User:" + userHash + "] " + format
	}
	logx.Warnf(tag, format, args...)
}

func RunServer(cfg *config.Config, tables []*sudoku.Table) {
	logx.InstallStd()

	// Listen on TCP port.
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.LocalPort))
	if err != nil {
		logx.Fatalf("Server", "%v", err)
	}
	logx.Infof("Server", "Server on :%d (Fallback: %s)", cfg.LocalPort, cfg.FallbackAddr)

	var revMgr *reverse.Manager
	if cfg.Reverse != nil && strings.TrimSpace(cfg.Reverse.Listen) != "" {
		revMgr = reverse.NewManager()
		revListen := strings.TrimSpace(cfg.Reverse.Listen)
		go func() {
			logx.Infof("Reverse", "entry on %s", revListen)
			if err := reverse.ServeEntry(revListen, revMgr); err != nil {
				logx.Warnf("Reverse", "entry error: %v", err)
			}
		}()
	}

	var tunnelSrv *httpmask.TunnelServer
	if cfg.HTTPMaskTunnelEnabled() {
		tunnelSrv = httpmask.NewTunnelServer(httpmask.TunnelServerOptions{
			Mode:     cfg.HTTPMask.Mode,
			PathRoot: cfg.HTTPMask.PathRoot,
			AuthKey:  cfg.Key,
			PassThroughOnReject: func() bool {
				if cfg.SuspiciousAction == "silent" {
					return true
				}
				return cfg.SuspiciousAction == "fallback" && strings.TrimSpace(cfg.FallbackAddr) != ""
			}(),
		})
	}

	// Graceful shutdown on SIGINT / SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logx.Infof("Server", "Shutting down...")
		l.Close()
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			// If the listener was closed by signal, exit gracefully.
			select {
			case <-sigCh:
				return
			default:
				continue
			}
		}
		go handleServerConn(c, cfg, tables, tunnelSrv, revMgr)
	}
}

func handleServerConn(rawConn net.Conn, cfg *config.Config, tables []*sudoku.Table, tunnelSrv *httpmask.TunnelServer, revMgr *reverse.Manager) {
	if tunnelSrv != nil {
		res, c, err := tunnelSrv.HandleConn(rawConn)
		if err != nil {
			logx.Warnf("Server/HTTP", "tunnel prelude failed: %v", err)
			rawConn.Close()
			return
		}
		switch res {
		case httpmask.HandleDone:
			return
		case httpmask.HandleStartTunnel:
			inner := *cfg
			inner.HTTPMask.Disable = true
			handleSudokuServerConn(c, rawConn, &inner, tables, false, revMgr)
			return
		case httpmask.HandlePassThrough:
			if r, ok := c.(interface{ IsHTTPMaskRejected() bool }); ok && r.IsHTTPMaskRejected() {
				handler.HandleSuspicious(c, rawConn, cfg)
				return
			}
			handleSudokuServerConn(c, rawConn, cfg, tables, true, revMgr)
			return
		default:
			rawConn.Close()
			return
		}
	}

	handleSudokuServerConn(rawConn, rawConn, cfg, tables, true, revMgr)
}

func handleSudokuServerConn(handshakeConn net.Conn, rawConn net.Conn, cfg *config.Config, tables []*sudoku.Table, allowFallback bool, revMgr *reverse.Manager) {
	// Use Tunnel Abstraction for Handshake and Upgrade
	tunnelConn, meta, err := tunnel.HandshakeAndUpgradeWithTablesMeta(handshakeConn, cfg, tables)
	if err != nil {
		if suspErr, ok := err.(*tunnel.SuspiciousError); ok {
			logx.Warnf("Security", "Suspicious connection: %v", suspErr.Err)
			// Only meaningful for direct TCP/legacy mask connections.
			if allowFallback {
				handler.HandleSuspicious(suspErr.Conn, rawConn, cfg)
			} else {
				rawConn.Close()
			}
		} else {
			logx.Warnf("Server", "Handshake failed: %v", err)
			rawConn.Close()
		}
		return
	}

	userHash := ""
	if meta != nil {
		userHash = meta.UserHash
	}

	// Read the first byte to detect session type (UoT / Mux / Reverse / normal).
	firstByte := make([]byte, 1)
	if _, err := io.ReadFull(tunnelConn, firstByte); err != nil {
		logx.Warnf("Server", "Failed to read first byte: %v", err)
		return
	}

	if firstByte[0] == tunnel.UoTMagicByte {
		logUserInfo("Server/UoT", userHash, "session start")
		if err := tunnel.HandleUoTServer(tunnelConn); err != nil {
			logUserWarn("Server/UoT", userHash, "session end: %v", err)
		} else {
			logUserInfo("Server/UoT", userHash, "session end")
		}
		return
	}

	if firstByte[0] == tunnel.MuxMagicByte {
		logUserInfo("Server/Mux", userHash, "session start")
		logConnect := func(addr string) {
			logUserInfo("Server/Mux", userHash, "Connecting to %s", addr)
		}
		if err := tunnel.HandleMuxServer(tunnelConn, logConnect); err != nil {
			logUserWarn("Server/Mux", userHash, "session end: %v", err)
		} else {
			logUserInfo("Server/Mux", userHash, "session end")
		}
		return
	}

	if firstByte[0] == tunnel.ReverseMagicByte {
		if revMgr == nil {
			logx.Warnf("Server/Reverse", "reverse proxy not enabled (missing reverse.listen)")
			return
		}
		logUserInfo("Server/Reverse", userHash, "session start")
		if err := reverse.HandleServerSession(tunnelConn, userHash, revMgr); err != nil {
			logUserWarn("Server/Reverse", userHash, "session end: %v", err)
		} else {
			logUserInfo("Server/Reverse", userHash, "session end")
		}
		return
	}

	// Not a special session: replay the peeked byte and read the target address.
	prefixedConn := tunnel.NewPreBufferedConn(tunnelConn, firstByte)

	// Read target address from the uplink.
	destAddrStr, _, _, err := protocol.ReadAddress(prefixedConn)
	if err != nil {
		logx.Warnf("Server", "Failed to read target address: %v", err)
		return
	}

	logUserInfo("Server", userHash, "Connecting to %s", destAddrStr)

	target, err := net.DialTimeout("tcp", destAddrStr, 10*time.Second)
	if err != nil {
		logx.Warnf("Server", "Connect target failed: %v", err)
		return
	}

	// Relay data.
	pipeConn(prefixedConn, target)
}
