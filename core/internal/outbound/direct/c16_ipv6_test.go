package direct

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"net/netip"
	"testing"
)

func TestK2IPv6TCPUDPRejectedBeforeIO(t *testing.T) {
	d := New(Options{DisableIPv6: true})
	_, e := d.DialTCP(context.Background(), outbound.Addr{Host: "2001:db8::1", Port: 443})
	if !errors.Is(e, ErrIPv6Disabled) {
		t.Fatal(e)
	}
	pc, e := d.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	if pc.(*packetConn).v6 != nil {
		t.Fatal("created udp6 socket while disabled")
	}
	_, e = pc.WriteTo([]byte("no send"), outbound.Addr{Host: "2001:db8::1", Port: 443})
	if !errors.Is(e, ErrIPv6Disabled) {
		t.Fatal(e)
	}
	ips, e := d.resolve(context.Background(), "::ffff:192.0.2.1")
	if e != nil || len(ips) != 1 || ips[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatal(ips, e)
	}
}
