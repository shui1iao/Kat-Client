package clientegress

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
	"testing"
)

func TestBindFailureSignalsOnceAndStaysClosed(t *testing.T) {
	p := fixturePolicy(t, func(string, syscall.RawConn) error { return errors.New("bind failed") })
	failed := p.Failed()
	select {
	case <-failed:
		t.Fatal("premature failure")
	default:
	}
	if err := p.Control(context.Background(), "tcp", "192.0.2.1:80", nil); err == nil {
		t.Fatal("bind succeeded")
	}
	select {
	case <-failed:
	default:
		t.Fatal("watcher not notified")
	}
	p.Fail()
	if p.Ready() {
		t.Fatal("failed lease recovered without validation")
	}
	sw := new(Switch)
	sw.FreezeNew()
	if err := sw.Control(context.Background(), "tcp", "127.0.0.1:9", nil); err == nil {
		t.Fatal("nil lease bypassed frozen socket control")
	}
	if _, err := sw.Bootstrap(context.Background(), "ip", "127.0.0.1"); err == nil {
		t.Fatal("nil lease bypassed frozen bootstrap")
	}
}
func TestPhysicalSourceEligibility(t *testing.T) {
	for _, tc := range []struct {
		ip        string
		skip      uint8
		dad, life uint32
		ok        bool
	}{
		{"192.0.2.1", 1, 4, 1, false}, {"192.0.2.1", 0, 1, 1, false}, {"192.0.2.1", 0, 2, 1, false}, {"2001:db8::1", 0, 4, 0, false}, {"::", 0, 4, 1, false}, {"127.0.0.1", 0, 4, 1, false}, {"ff02::1", 0, 4, 1, false}, {"192.0.2.2", 0, 3, 1, true}, {"2001:db8::1", 0, 4, 1, true}} {
		if got := UsableUnicastSource(netip.MustParseAddr(tc.ip), tc.skip, tc.dad, tc.life); got != tc.ok {
			t.Fatal(tc, got)
		}
	}
}
