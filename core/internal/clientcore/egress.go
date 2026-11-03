package clientcore

import (
	"net/netip"

	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
)

func policyHooks(p *clientegress.Policy) *kernel.ClientEgress {
	if p == nil {
		return nil
	}
	var dns []netip.Addr
	for _, s := range p.Options.DNS {
		if ip, e := netip.ParseAddr(s); e == nil {
			dns = append(dns, ip.Unmap())
		}
	}
	return &kernel.ClientEgress{Failure: p.Fail, Control: p.Control, PacketControl: p.PacketControl, Bootstrap: p.Bootstrap, DNSServers: dns}
}
func (h *Host) withEgress(c kernel.Config) kernel.Config {
	c.SetClientEgress(policyHooks(h.egress))
	return c
}
func (h *Host) egressViewLocked() clientegress.View {
	o := h.egressOptions
	if o.DNS == nil {
		o.DNS = []string{}
	}
	v := clientegress.View{Options: o, Generation: h.egressGeneration, Coverage: []string{}}
	if h.egress != nil {
		v.Ready = h.server != nil && h.localReady && h.egress.Ready()
		v.Coverage = append([]string(nil), clientegress.Coverage...)
	}
	return v
}
func (h *Host) EgressGet() any { h.mu.Lock(); defer h.mu.Unlock(); return h.egressViewLocked() }

// Only the trusted native host may dispatch this method. The public WebView
// bridge must reject network.egress.*; the sidecar never listens publicly.
func (h *Host) EgressSet(o clientegress.Options) (any, *Error) {
	if !clientegress.Supported {
		return nil, fail("unsupported_platform", "network.egress", "Physical egress control requires Windows")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if o.Enabled && (h.server == nil || !h.localReady) {
		return nil, fail("not_ready", "local", "Start both local proxies before enabling egress")
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
		o = clientegress.Options{DNS: []string{}}
	}
	if p != nil {
		p.SetIPv6(h.doc.client.IPv6)
	}
	return h.transitionEgressLocked(p, o)
}

func (h *Host) transitionEgressLocked(p *clientegress.Policy, o clientegress.Options) (any, *Error) {
	h.cancelBootstrapLocked()
	// Native host has removed its TUN routes first. Close this client's entire
	// old instance, including provider/DNS/protocol pools and retained flows.
	// Normal document reload does not use this disruptive transition.
	running := h.server != nil
	if running {
		_ = h.stopLocked()
	}
	h.egress, h.egressOptions = p, o
	if running {
		if e := h.startLocked(); e != nil {
			if p != nil {
				p.Fail()
			}
			return nil, e
		}
	}
	h.egressGeneration++
	return h.egressViewLocked(), nil
}
