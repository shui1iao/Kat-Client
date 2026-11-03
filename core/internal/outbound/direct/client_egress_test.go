package direct

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"net"
	"testing"
	"time"
)

func TestClientPacketControlBeforeRemoteSendAndLoopbackExemption(t *testing.T) {
	calls := 0
	failures := 0
	d := New(Options{PacketControl: func(string, *net.UDPConn) error { calls++; return errors.New("do not send remote packets") }, PacketFailure: func() { failures++ }})
	pc, e := d.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	for _, host := range []string{"192.0.2.1", "2001:db8::1"} {
		if _, e = pc.WriteTo([]byte("must-not-escape"), outbound.Addr{Host: host, Port: 9}); e == nil {
			t.Fatal("uncontrolled remote datagram sent")
		}
	}
	if calls == 0 || failures != 2 {
		t.Fatal("remote hook missing")
	}
	target, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	target.SetReadDeadline(time.Now().Add(time.Second))
	before := calls
	if _, e = pc.WriteTo([]byte("local"), outbound.Addr{Host: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port)}); e != nil {
		t.Fatal(e)
	}
	var b [8]byte
	n, _, e := target.ReadFromUDP(b[:])
	if e != nil || string(b[:n]) != "local" || calls != before {
		t.Fatal("loopback was physically bound")
	}
}
