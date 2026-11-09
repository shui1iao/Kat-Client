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
	"github.com/shui1iao/Kat/internal/route"
	"net"
	"net/netip"
	"strings"
)

type UDPAssociationInfo struct {
	ID             string   `json:"id"`
	Policy         string   `json:"policy"`
	Outbound       string   `json:"outbound"`
	Epoch          uint64   `json:"epoch"`
	Binding        string   `json:"binding"`
	LocalEndpoints []string `json:"local_endpoints,omitempty"`
	Shared         bool     `json:"shared,omitempty"`
	ReplyPeer      string   `json:"reply_peer,omitempty"`
	UnmatchedPeer  bool     `json:"unmatched_peer,omitempty"`
}
type FlowDetails struct {
	UDPAssociation  *UDPAssociationInfo `json:"udp_association,omitempty"`
	ProcessStatus   string              `json:"process_status,omitempty"`
	ProcessPID      uint32              `json:"process_pid,omitempty"`
	ProcessCreation uint64              `json:"process_creation,omitempty"`
	DNSRCode        *uint16             `json:"dns_rcode,omitempty"`
	DNSQueryType    uint16              `json:"dns_query_type,omitempty"`
	ProcessName     string              `json:"process_name,omitempty"`
	ProcessPath     string              `json:"process_path,omitempty"`
	DomainSuffix    string              `json:"domain_suffix,omitempty"`
	FlowID          string              `json:"flow_id,omitempty"`
	InboundKind     string              `json:"inbound_kind,omitempty"`
	SourceAddr      string              `json:"source_addr,omitempty"`
	DestHost        string              `json:"dest_host,omitempty"`
	Sniffed         bool                `json:"sniffed,omitempty"`
	DestIP          string              `json:"dest_ip,omitempty"`
	DestIPs         []string            `json:"dest_ips,omitempty"`
	RemoteDNS       bool                `json:"remote_dns,omitempty"`
	ErrorText       string              `json:"error_text,omitempty"`
	ErrorStage      string              `json:"error_stage,omitempty"`
}

func (f *flow) initDetails(ctx context.Context, target Address) {
	f.details.FlowID = fmt.Sprintf("%d:%d", f.s.started.UnixNano(), f.id)
	if t, ok := tunFlowOf(ctx); ok {
		f.details.SourceAddr, f.details.InboundKind = t.Source.String(), "tun"
		f.details.DestIP = t.Destination.Addr().String()
		return
	}
	if _, e := netip.ParseAddr(target.Host); e != nil {
		f.details.DestHost = target.Host
	}
	if q, ok := processQuery(ctx, f.network, target); ok {
		f.httpObservation = procattr.HTTPFlowObservation(q)
		if f.httpObservation != nil && f.httpObservation.Bind != nil {
			f.httpObservation.Bind(f.id)
		}
		if source, kind, ok := procattr.HTTPFlowOrigin(q); ok {
			f.details.SourceAddr, f.details.InboundKind = source, kind
		}
	}
}

// Display admission is independent of route admission. Saturation skips display
// only; a rule requiring process attribution still performs its lazy query.
var detailSlots = make(chan struct{}, 16)

func (f *flow) scheduleDetails(ctx context.Context, target Address) {
	if f == nil || f.s.connectionSink == nil || target.Port == 0 {
		return
	}
	if t, ok := tunFlowOf(ctx); ok && (t.Destination.Port() == 53 || f.network == "udp") {
		return
	}
	f.detailsOnce.Do(func() {
		select {
		case detailSlots <- struct{}{}:
		default:
			return
		}
		go func() {
			defer func() { <-detailSlots }()
			if ctx.Err() != nil || f.ended.Load() {
				return
			}
			q, ok := processQuery(ctx, f.network, target)
			if !ok {
				return
			}
			id := processIdentity(ctx, f.network, target)()
			source, kind := procattr.OriginFromIdentity(q, id)
			if kind == "" && source != "" {
				if im := inboundMetaOf(ctx); im != nil {
					switch im.typ {
					case "socks5":
						kind = "socks"
					case "http":
						kind = "http"
					default:
						source = ""
					}
				}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.ended.Load() || ctx.Err() != nil || !procattr.IdentityCurrent(id) {
				return
			}
			if t, ok := tunFlowOf(ctx); ok {
				source, kind = t.Source.String(), "tun"
			}
			f.details.SourceAddr, f.details.InboundKind = source, kind
			f.details.ProcessStatus = id.Status
			f.details.ProcessPID, f.details.ProcessCreation = id.PID, id.Stamp
			if id.Status == "known" {
				f.details.ProcessName, f.details.ProcessPath = id.Name, id.Path
			}
		}()
	})
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
	var attribution *route.ProcessUnavailableError
	var dns *net.DNSError
	var record tls.RecordHeaderError
	var cert x509.UnknownAuthorityError
	switch {
	case errors.As(err, &attribution):
		return "process"
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

// Called with a per-datagram once cell; route and display share only THAT query.
func (f *flow) tunProcess(ctx context.Context, target Address) {
	if f == nil || f.s.connectionSink == nil {
		return
	}
	id := processIdentity(ctx, "udp", target)()
	f.tunIdentity(id)
}
func (f *flow) tunIdentity(id procattr.Identity) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.details.ProcessStatus = id.Status
	f.details.ProcessName, f.details.ProcessPath = "", ""
	f.details.ProcessPID, f.details.ProcessCreation = 0, 0
	if id.Status == "known" {
		f.details.ProcessName, f.details.ProcessPath = id.Name, id.Path
		f.details.ProcessPID, f.details.ProcessCreation = id.PID, id.Stamp
	}
}
