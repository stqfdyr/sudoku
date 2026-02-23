package app

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/saba-futai/sudoku/internal/config"
	"github.com/saba-futai/sudoku/internal/tunnel"
	"github.com/saba-futai/sudoku/pkg/geodata"
	"github.com/saba-futai/sudoku/pkg/logx"
)

var directDial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

func dialTarget(network string, src net.Addr, destAddrStr string, destIP net.IP, cfg *config.Config, geoMgr *geodata.Manager, dialer tunnel.Dialer) (net.Conn, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	decision := decideRoute(ctx, cfg, geoMgr, destAddrStr, destIP)
	cancel()

	logRoute(network, src, destAddrStr, decision.match, decision.shouldProxy)

	if decision.shouldProxy {
		conn, err := dialer.Dial(destAddrStr)
		if err != nil {
			logx.Warnf("Proxy", "Dial Failed: %v", err)
			return nil, false
		}
		return conn, true
	}

	directAddr := strings.TrimSpace(decision.directAddr)
	if directAddr == "" {
		directAddr = destAddrStr
	}

	dConn, err := directDial("tcp", directAddr, 5*time.Second)
	if err != nil && strings.TrimSpace(destAddrStr) != "" && directAddr != destAddrStr {
		dConn, err = directDial("tcp", destAddrStr, 5*time.Second)
	}
	if err != nil {
		logx.Warnf("Direct", "Dial Failed: %v", err)
		return nil, false
	}
	return dConn, true
}
