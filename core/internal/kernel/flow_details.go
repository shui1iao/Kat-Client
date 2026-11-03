package kernel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/logsafe"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/procattr"
	"net"
	"net/netip"
	"strings"
)

type FlowDetails struct {
	ProcessName  string   `json:"process_name,omitempty"`
	ProcessPath  string   `json:"process_path,omitempty"`
	DomainSuffix string   `json:"domain_suffix,omitempty"`
	FlowID       string   `json:"flow_id,omitempty"`
	InboundKind  string   `json:"inbound_kind,omitempty"`
	SourceAddr   string   `json:"source_addr,omitempty"`
	DestHost     string   `json:"dest_host,omitempty"`
	Sniffed      bool     `json:"sniffed,omitempty"`
	DestIP       string   `json:"dest_ip,omitempty"`
	DestIPs      []string `json:"dest_ips,omitempty"`
	RemoteDNS    bool     `json:"remote_dns,omitempty"`
	ErrorText    string   `json:"error_text,omitempty"`
	ErrorStage   string   `json:"error_stage,omitempty"`
}

func (f *flow) initDetails(ctx context.Context, target Address) {
	f.details.FlowID = fmt.Sprintf("%d:%d", f.s.started.UnixNano(), f.id)
	if _, e := netip.ParseAddr(target.Host); e != nil {
		f.details.DestHost = target.Host
	}
	f.originDetails(ctx, target)
	if f.s.connectionSink != nil {
		id := processIdentity(ctx, f.network, target)()
		if id.Status == "known" {
			f.mu.Lock()
			f.details.ProcessName, f.details.ProcessPath = id.Name, id.Path
			f.mu.Unlock()
		}
	}
}
func (f *flow) originDetails(ctx context.Context, target Address) {
	if f == nil || f.s.connectionSink == nil {
		return
	}
	im := inboundMetaOf(ctx)
	if im == nil {
		return
	}
	q := procattr.Query{Network: f.network, Source: im.remote, Destination: im.local, ControlSource: im.remote, ControlDestination: im.local}
	if ip, e := netip.ParseAddr(target.Host); e == nil {
		q.Target = netip.AddrPortFrom(ip.Unmap(), target.Port)
	}
	if u, ok := ctx.Value(udpProcessKey{}).(udpProcessTuple); ok {
		q.Source = u.source
		q.Destination = u.destination
	}
	source, kind := procattr.FlowOrigin(ctx, q)
	if kind == "" && source != "" {
		switch im.typ {
		case "socks5":
			kind = "socks"
		case "http":
			kind = "http"
		default:
			source = ""
		}
	}
	f.mu.Lock()
	f.details.SourceAddr, f.details.InboundKind = source, kind
	f.mu.Unlock()
}
func (f *flow) dialIPs(ips []netip.Addr, chosen netip.Addr) {
	if f == nil || f.s.connectionSink == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.details.DestIPs = nil
	for _, ip := range ips {
		f.details.DestIPs = append(f.details.DestIPs, ip.String())
	}
	if chosen.IsValid() {
		f.details.DestIP = chosen.String()
		f.details.RemoteDNS = false
	}
}
func (f *flow) setError(err error) {
	if f == nil || f.s.connectionSink == nil || err == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.details.ErrorText = logsafe.Text(err.Error())
	f.details.ErrorStage = errorStage(err)
}
func errorStage(err error) string {
	var dns *net.DNSError
	var record tls.RecordHeaderError
	var cert x509.UnknownAuthorityError
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed):
		return "canceled"
	case errors.Is(err, errRouteReject) || errors.Is(err, outbound.ErrRejected) || errors.Is(err, errBlocked):
		return "rule_reject"
	case errors.As(err, &dns):
		return "dns"
	case errors.As(err, &record) || errors.As(err, &cert) || strings.Contains(strings.ToLower(err.Error()), "tls:"):
		return "tls"
	}
	if strings.Contains(strings.ToLower(err.Error()), "handshake") {
		return "proxy_handshake"
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return "connect"
	}
	return ""
}
