package kernel

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	at "github.com/shui1iao/Kat/internal/outbound/anytls"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/outbound/ss"
	"net"
	"testing"
	"time"
)

// Three tiny datagrams per protocol, using only Kat's own local server; no GPL
// interop executable, new protocol, concurrency load or external server.
func TestM2ExistingProxyUDPUsesOneMultiDestinationAssociation(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "anytls"} {
		t.Run(protocol, func(t *testing.T) {
			in := Inbound{Protocol: protocol}
			if protocol == "shadowsocks" {
				in.SS = &SSOptions{Method: "aes-128-gcm", Password: "m2-local-fixture"}
			} else {
				cert, _ := testCert(t)
				in.TLS = cert
				in.AnyTLS = &AnyTLSOptions{Password: "m2-local-fixture"}
			}
			server := startTest(t, in, nil)
			addr := server.Addresses()[0].(*net.TCPAddr)
			options := outbound.Options{Name: "m2-local-proxy", Type: protocol, Server: "127.0.0.1", Port: uint16(addr.Port), Password: "m2-local-fixture", Method: "aes-128-gcm", TLS: &outbound.TLSOptions{Insecure: true}}
			if protocol == "shadowsocks" {
				options.TLS = nil
			} else {
				options.Method = ""
			}
			var ob outbound.Outbound
			var e error
			if protocol == "shadowsocks" {
				ob, e = ss.New(options, direct.New(direct.Options{}))
			} else {
				ob, e = at.New(options, direct.New(direct.Options{}))
			}
			if e != nil {
				t.Fatal(e)
			}
			defer ob.Close()
			ctx, cancel := context.WithTimeout(outbound.WithEndpointIndependent(context.Background(), true), time.Second)
			defer cancel()
			pc, e := ob.ListenPacket(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer pc.Close()
			a, b := stage4Socket(t, "udp4", "127.0.0.1"), stage4Socket(t, "udp4", "127.0.0.1")
			for _, peer := range []*net.UDPConn{a, b, a} {
				ap := peer.LocalAddr().(*net.UDPAddr).AddrPort()
				target := outbound.Addr{Host: ap.Addr().String(), Port: ap.Port()}
				_ = pc.SetWriteDeadline(time.Now().Add(time.Second))
				if n, e := pc.WriteTo([]byte("up"), target); e != nil || n != 2 {
					t.Fatal(n, e)
				}
				_ = peer.SetReadDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 128)
				n, src, e := peer.ReadFromUDPAddrPort(buf)
				if e != nil || string(buf[:n]) != "up" {
					t.Fatal("proxy upload", e)
				}
				if _, e = peer.WriteToUDPAddrPort([]byte("down"), src); e != nil {
					t.Fatal(e)
				}
				_ = pc.SetReadDeadline(time.Now().Add(time.Second))
				n, actual, e := pc.ReadFrom(buf)
				if e != nil || actual != target || string(buf[:n]) != "down" {
					t.Fatal("proxy peer identity", actual, e)
				}
			}
			no := false
			options.UDP = &no
			var disabled outbound.Outbound
			if protocol == "shadowsocks" {
				disabled, e = ss.New(options, direct.New(direct.Options{}))
			} else {
				disabled, e = at.New(options, direct.New(direct.Options{}))
			}
			if e != nil {
				t.Fatal(e)
			}
			defer disabled.Close()
			if _, e = disabled.ListenPacket(context.Background()); !errors.Is(e, outbound.ErrUDPUnsupported) {
				t.Fatal("unsupported hidden", e)
			}
		})
	}
}
