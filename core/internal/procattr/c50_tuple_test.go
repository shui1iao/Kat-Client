package procattr

import (
	"context"
	"net/netip"
	"testing"
)

func TestC50LookupTupleCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	q := Query{Network: "udp", Source: netip.MustParseAddrPort("127.0.0.1:45000"), Destination: netip.MustParseAddrPort("203.0.113.50:443")}
	got := LookupTuple(ctx, q)
	// The common budget rejects cancellation before platform/native lookup.
	if got.Status != "unknown" || got.Cause != "process:unknown" || got.SessionEpoch != 0 || got.Name != "" {
		t.Fatalf("tuple lookup used stale proxy/session identity: %+v", got)
	}
}
