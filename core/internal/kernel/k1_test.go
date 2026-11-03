package kernel

import (
	"context"
	"testing"
)

func TestK1CaptureNestedGroupOldTCPAndUDPOnly(t *testing.T) {
	s := startTest(t, inFor("socks5", nil), func(c *Config) { c.SetConnectionSink(func(ConnectionEvent) {}) })
	a, ac := s.newFlow(context.Background(), "tcp", Address{Host: "a.invalid", Port: 443})
	defer a.end("ok")
	a.route(-1, []string{"Final", "AI", "node"})
	b, bc := s.newFlow(context.Background(), "udp", Address{Host: "b.invalid", Port: 53})
	defer b.end("ok")
	b.route(-1, []string{"Final", "AI", "node"})
	other, oc := s.newFlow(context.Background(), "tcp", Address{Host: "c.invalid", Port: 443})
	defer other.end("ok")
	other.route(-1, []string{"Emby", "node"})
	ids := s.ClientGroupConnectionIDs([]string{"AI"})
	fresh, fc := s.newFlow(context.Background(), "tcp", Address{Host: "new.invalid", Port: 443})
	defer fresh.end("ok")
	fresh.route(-1, []string{"AI", "node"})
	if s.ClientCloseConnections(ids) != 2 || ac.Err() == nil || bc.Err() == nil || oc.Err() != nil || fc.Err() != nil {
		t.Fatal("wrong chain or post-capture scope")
	}
}
