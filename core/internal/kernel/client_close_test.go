package kernel

import (
	"context"
	"testing"
	"time"
)

func TestClientCloseSelectedRealTCPAndUDP(t *testing.T) {
	s := startTest(t, inFor("socks5", nil), func(c *Config) { c.SetConnectionSink(func(ConnectionEvent) {}) })
	generation := s.StatsView().Reload.Generation
	target := echoTCP(t)
	a, code := socksConnect(t, s, target)
	if code != 0 {
		t.Fatal(code)
	}
	defer a.Close()
	b, code := socksConnect(t, s, target)
	if code != 0 {
		t.Fatal(code)
	}
	defer b.Close()
	udp, _ := echoUDP(t)
	control, u, relay := socksAssociate(t, s, 0)
	defer control.Close()
	socksUDPSend(t, u, relay, udp, []byte("before"), 0)
	if string(socksUDPRead(t, u)) != "before" {
		t.Fatal("UDP fixture")
	}
	active, _ := s.ClientConnections(500)
	if len(active) != 3 {
		t.Fatal(active)
	}
	tcp := []uint64{}
	var udpID uint64
	for _, v := range active {
		if v.Network == "udp" {
			udpID = v.ID
		} else {
			tcp = append(tcp, v.ID)
		}
	}
	if s.ClientCloseConnections([]uint64{tcp[0], tcp[0], 999999}) != 1 {
		t.Fatal("single/duplicate/nonexistent actual count")
	}
	if s.ClientCloseConnections([]uint64{tcp[0], 999999}) != 0 {
		t.Fatal("already requested counted")
	}
	a.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := a.Read(make([]byte, 1)); e == nil {
		t.Fatal("TCP still open")
	}
	b.SetDeadline(time.Now().Add(time.Second))
	writeAll(b, []byte("other"))
	if v, e := readN(b, 5); e != nil || string(v) != "other" {
		t.Fatal("unselected TCP affected", e)
	}
	if s.ClientCloseConnections([]uint64{udpID, tcp[1]}) != 2 {
		t.Fatal("batch close")
	}
	waitFor(t, func() bool { a, _ := s.ClientConnections(500); return len(a) == 0 })
	socksUDPSend(t, u, relay, udp, []byte("after"), 0)
	u.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	if _, _, e := u.ReadFromUDP(make([]byte, 64)); e == nil {
		t.Fatal("closed UDP accepted packet")
	}
	_, closed := s.ClientConnections(500)
	if len(closed) != 3 {
		t.Fatal("closed history missing", closed)
	}
	if s.ClientCloseConnections([]uint64{udpID, tcp[0], tcp[1]}) != 0 {
		t.Fatal("ended ids counted")
	}
	if s.StatsView().Reload.Generation != generation {
		t.Fatal("close reloaded kernel")
	}
}
func TestClientCloseCapturedLogicalFlowCancellation(t *testing.T) {
	// TUN feeds the same logical TCP/UDP flow registry; cancellation is agnostic
	// to inbound transport. Verify both contexts and an unselected flow separately.
	s := startTest(t, inFor("socks5", nil), func(c *Config) { c.SetConnectionSink(func(ConnectionEvent) {}) })
	a, ac := s.newFlow(context.Background(), "tcp", Address{Host: "tun.invalid", Port: 443})
	defer a.end("ok")
	b, bc := s.newFlow(context.Background(), "udp", Address{Host: "tun.invalid", Port: 53})
	defer b.end("ok")
	other, oc := s.newFlow(context.Background(), "tcp", Address{Host: "other.invalid", Port: 443})
	defer other.end("ok")
	if s.ClientCloseConnections([]uint64{a.id, b.id}) != 2 {
		t.Fatal("not closed")
	}
	if ac.Err() == nil || bc.Err() == nil || oc.Err() != nil {
		t.Fatal("wrong cancellation scope")
	}
}
