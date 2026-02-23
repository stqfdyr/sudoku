package app

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/saba-futai/sudoku/internal/config"
	"github.com/saba-futai/sudoku/pkg/dnsutil"
	"github.com/saba-futai/sudoku/pkg/geodata"
	"github.com/saba-futai/sudoku/pkg/logx"
)

var lookupIPsWithCache = dnsutil.LookupIPsWithCache

type routeDecision struct {
	shouldProxy bool
	match       string
	directAddr  string
}

func decideRoute(ctx context.Context, cfg *config.Config, geoMgr *geodata.Manager, destAddr string, destIP net.IP) routeDecision {
	decision := routeDecision{shouldProxy: true, match: "MODE(global)", directAddr: destAddr}
	if cfg == nil {
		decision.match = "CFG(nil)"
		return decision
	}

	switch cfg.ProxyMode {
	case "direct":
		return routeDecision{shouldProxy: false, match: "MODE(direct)", directAddr: destAddr}
	case "global":
		return routeDecision{shouldProxy: true, match: "MODE(global)", directAddr: destAddr}
	case "pac":
		if geoMgr == nil {
			decision.match = "PAC(no-rules)"
			return decision
		}

		if ok, m := geoMgr.MatchCN(destAddr, destIP); ok {
			return routeDecision{shouldProxy: false, match: m.String(), directAddr: destAddr}
		}
		if destIP != nil {
			decision.match = "PAC/NONE"
			return decision
		}

		host, port, err := net.SplitHostPort(destAddr)
		if err != nil {
			decision.match = "PAC/ADDR_INVALID"
			return decision
		}

		if ctx == nil {
			ctx = context.Background()
		}
		ips, err := lookupIPsWithCache(ctx, host)
		if err != nil || len(ips) == 0 {
			decision.match = "PAC/DNS_FAIL"
			return decision
		}

		for _, ip := range ips {
			if ok, m := geoMgr.MatchCN(destAddr, ip); ok {
				return routeDecision{
					shouldProxy: false,
					match:       "DNS->" + m.String(),
					directAddr:  net.JoinHostPort(ip.String(), port),
				}
			}
		}

		decision.match = "PAC/NONE"
		return decision
	default:
		decision.match = "MODE(unknown)"
		return decision
	}
}

func logRoute(network string, src net.Addr, destAddr string, match string, shouldProxy bool) {
	srcStr := "<unknown>"
	if src != nil {
		srcStr = src.String()
	}
	action := "PROXY"
	if !shouldProxy {
		action = "DIRECT"
	}
	actionText := logx.Bold(logx.Magenta(action))
	if action == "DIRECT" {
		actionText = logx.Bold(logx.Green(action))
	}
	logx.Infof(strings.ToUpper(strings.TrimSpace(network)), "%s --> %s match %s using %s", srcStr, destAddr, logx.Yellow(match), actionText)
}

func resolveUDPAddr(ctx context.Context, addr string) (*net.UDPAddr, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, fmt.Errorf("empty address")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resolved, err := dnsutil.ResolveWithCache(ctx, addr)
	if err != nil {
		return nil, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", resolved)
	if err != nil {
		return nil, err
	}
	if udpAddr != nil {
		udpAddr.IP = normalizeIP(udpAddr.IP)
	}
	return udpAddr, nil
}
