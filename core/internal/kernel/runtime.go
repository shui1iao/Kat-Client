package kernel

import (
	"github.com/shui1iao/Kat/internal/stats"
	"time"
)

// Version is supplied by the client host.
var Version = "dev"

func (k *core) notice(lv logLevel, line string) {
	if k != nil && k.log != nil {
		_ = k.log.emit(lv, []byte(line+"\n"))
	}
}

type ClientStatusView struct {
	UptimeMS   int64
	UpRate     float64
	DownRate   float64
	TCP        int64
	UDP        int64
	Cumulative stats.ClientSnapshot
	Providers  []ProviderView
}

func (s *Server) ClientStatusView() ClientStatusView {
	k := s.core
	up, down, _ := k.reg.Rate()
	return ClientStatusView{
		UptimeMS: time.Since(k.started).Milliseconds(), UpRate: up, DownRate: down,
		TCP: k.tcpFlows.Load(), UDP: k.counters.UDP.Load(),
		Cumulative: k.reg.ClientSnapshot(), Providers: k.providerViews(),
	}
}
