package clientcore

import (
	"context"
	"net/netip"
	"time"

	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
)

func policyHooks(p *clientegress.Policy) *kernel.ClientEgress {
	if p == nil {
		return nil
	}
	var dns []netip.Addr
	for _, d := range p.Options.DNS {
		ip, _ := netip.ParseAddr(d.Address)
		if d.Scope == 0 {
			dns = append(dns, ip)
		}
	}
	return &kernel.ClientEgress{Failure: p.Fail, Control: p.Control, PacketControl: p.PacketControl, Bootstrap: p.Bootstrap, DNSServers: dns, SystemQuery: p.SystemQuery, DNSContext: p.DNSContext}
}
func (h *Host) withEgress(c kernel.Config) kernel.Config {
	if clientegress.Supported {
		s := &h.egressSwitch
		s.SetIPv6(h.doc.client.IPv6)
		c.SetClientEgress(&kernel.ClientEgress{UDPBinding: s.UDPBinding, UDPAssociationBinding: s.UDPAssociationBinding, Active: s.Enabled, Servers: s.Servers, Failure: s.Fail, Control: s.Control, PacketSource: s.PacketSource, PacketControl: s.PacketControl, PacketRelease: s.PacketRelease, DialContext: s.DialContext, Bootstrap: s.Bootstrap, SystemQuery: s.SystemQuery, DNSContext: s.DNSContext})
	} else {
		c.SetClientEgress(policyHooks(h.egress))
	}
	return c
}
func (h *Host) egressViewLocked() clientegress.View {
	h.syncTUNEgressLocked()
	o := h.egressOptions.Clone()
	var revision uint64
	if h.egress != nil {
		o, revision = h.egress.DNSSnapshot()
	}
	o.Schema = clientegress.Schema
	if o.DNS == nil {
		o.DNS = []clientegress.DNSEndpoint{}
	}
	v := clientegress.View{Options: o, Generation: h.egressGeneration, DNSRevision: revision, Coverage: []string{}}
	if h.egress != nil {
		v.Ready = !h.egressFrozen && h.server != nil && h.localReady && h.egress.Ready()
		v.Coverage = append([]string(nil), clientegress.Coverage...)
	}
	return v
}
func (h *Host) EgressGet() any { h.mu.Lock(); defer h.mu.Unlock(); return h.egressViewLocked() }

// Only the trusted native host may dispatch this method. The public WebView
// bridge must reject network.egress.*; the sidecar never listens publicly.
func (h *Host) EgressSet(o clientegress.Options) (any, *Error) {
	if h.tunSession != nil {
		return nil, fail("TUN_ENGINE_RETIRED", "network.egress", "Physical lifecycle is owned by core TUN Manager")
	}
	if o.Schema != clientegress.Schema {
		return nil, fail("invalid_params", "schema", "Physical egress v3 required")
	}
	if !clientegress.Supported {
		return nil, fail("unsupported_platform", "network.egress", "Physical egress control requires Windows")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if o.Enabled && (h.server == nil || !h.localReady) {
		return nil, fail("not_ready", "local", "Start both local proxies before enabling egress")
	}
	if !o.Enabled && h.egress == nil {
		return h.egressViewLocked(), nil
	}
	if o.Enabled && h.egress != nil && h.egress.Ready() {
		current, _ := h.egress.DNSSnapshot()
		if current.Fingerprint == o.Fingerprint {
			return h.egressViewLocked(), nil
		}
	}
	var p *clientegress.Policy
	if o.Enabled {
		var e error
		p, e = clientegress.New(o)
		if e != nil {
			if h.egress != nil {
				h.egress.Fail()
				h.cancelBootstrapLocked()
			}
			return nil, fail("egress_failed", "network.egress", "Physical interface, DNS or socket control validation failed")
		}
	} else {
		o = clientegress.Options{Schema: clientegress.Schema, DNS: []clientegress.DNSEndpoint{}}
	}
	if p != nil {
		p.SetIPv6(h.doc.client.IPv6)
	}
	return h.transitionEgressLocked(p, o)
}

func (h *Host) transitionEgressLocked(p *clientegress.Policy, o clientegress.Options) (any, *Error) {
	h.cancelBootstrapLocked()
	// The stable switch invalidates exact old sockets (including idle protocol
	// pools) before accepting new dials, without touching groups or listeners.
	h.egressSwitch.Replace(p)
	h.egress, h.egressOptions = p, o.Clone()
	if h.server != nil {
		_, _ = h.server.ClearDNSCache(true)
	}
	h.egressGeneration++
	h.logs.record(kernel.ClientLogEvent{Time: time.Now(), Level: "info", Event: "egress_committed", Generation: h.egressGeneration})
	return h.egressViewLocked(), nil
}

func (h *Host) refreshDNS(ctx context.Context, revision uint64, fingerprint string) (any, *Error) {
	return nil, fail("TUN_ENGINE_RETIRED", "dns", "DNS revision lifecycle is owned by core TUN Manager")
}
