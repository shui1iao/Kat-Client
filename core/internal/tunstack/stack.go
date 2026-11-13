// Stack initialization is based on tun2socks v2.7.0 core (MIT).
// Copyright (c) 2019 Jason Lyu. See LICENSE.tun2socks.
// Kat modifications: instance ownership, custom UDP, admission/epoch, cancellation;
// no default tunnel/proxy/ICMP echo handler or global engine is imported.
package tunstack

import (
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"net/netip"
	"runtime"
)

func (r *Runtime) initStack() error {
	r.link = channel.New(4096, MTU, "")
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6}})
	r.stack = s
	// On Windows local Wintun rings, ACK/SACK timing under RACK triggers
	// measured recovery storms that collapse download cwnd; use classic
	// SACK + 3-DupACK + RTO recovery on Windows without claiming every
	// retransmission is spurious.
	if runtime.GOOS == "windows" {
		opt := tcpip.TCPRecovery(0)
		if e := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); e != nil {
			return fmt.Errorf("tunstack TCP recovery: %s", e)
		}
	}
	tf := tcp.NewForwarder(s, 0, 256, func(req *tcp.ForwarderRequest) {
		if !r.reserve() {
			req.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, e := req.CreateEndpoint(&wq)
		if e != nil {
			req.Complete(true)
			r.release(nil)
			return
		}
		f := flowID(req.ID(), TCP) // Complete releases the request segment/ID.
		req.Complete(false)
		c := gonet.NewTCPConn(&wq, ep)
		if !r.enter(c, &f) {
			r.release(c)
			return
		}
		defer r.release(c)
		_ = r.cfg.Ingress.HandleTCP(r.ctx, f, c)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	// UDP is source-oriented; gVisor still validates/reassembles IP/UDP.
	s.SetTransportProtocolHandler(udp.ProtocolNumber, r.udpPacket)
	nic := s.NextNICID()
	if e := s.CreateNIC(nic, r.link); e != nil {
		return fmt.Errorf("tunstack NIC: %s", e)
	}
	if e := s.SetPromiscuousMode(nic, true); e != nil {
		return fmt.Errorf("tunstack promiscuous: %s", e)
	}
	if e := s.SetSpoofing(nic, true); e != nil {
		return fmt.Errorf("tunstack spoofing: %s", e)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nic}, {Destination: header.IPv6EmptySubnet, NIC: nic}})
	return nil
}
func flowID(id stack.TransportEndpointID, p Protocol) Flow {
	src, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	dst, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	return Flow{Source: netip.AddrPortFrom(src.Unmap(), id.RemotePort), Destination: netip.AddrPortFrom(dst.Unmap(), id.LocalPort), Protocol: p}
}
