package kernel

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// anyTLSIdentitiesJSON returns n AnyTLS inbounds with distinct passwords and
// the given extra "anytls" members (e.g. `,"max_streams":64`).
func anyTLSIdentitiesJSON(n int, extra string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf(`{"protocol":"anytls","listen":"127.0.0.1:0","anytls":{"password":"identity-%d"%s}}`, i, extra)
	}
	return strings.Join(parts, ",")
}

func TestDefaultLimitsValues(t *testing.T) {
	c, e := Load(writeConfig(t, `{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}]}`))
	if e != nil {
		t.Fatal(e)
	}
	l := c.Limits
	for _, v := range []struct {
		name      string
		got, want int
	}{
		{"connections", l.Connections, 4096},
		{"logical_streams", l.LogicalStreams, 8192},
		{"handshakes", l.Handshakes, 512},
		{"dials", l.Dials, 512},
		{"udp_associations", l.UDPAssociations, 1024},
		{"udp_targets", l.UDPTargets, 256},
		// Unchanged defaults.
		{"udp_queue", l.UDPQueue, 16},
		{"udp_queue_bytes", l.UDPQueueBytes, 16 * maxDatagram},
		{"buffer_size", l.BufferSize, 16384},
		{"pool_buffers", l.PoolBuffers, 128},
	} {
		if v.got != v.want {
			t.Errorf("%s default = %d, want %d", v.name, v.got, v.want)
		}
	}
}

func TestLogicalStreamsAutoCoversAnyTLSIdentities(t *testing.T) {
	for _, tc := range []struct {
		identities int
		extra      string
		want       int
	}{
		{1, "", 8192},
		{2, "", 8192},  // 2 x 4096 = 8192
		{3, "", 12288}, // previously rejected: 3 x 64 <= 256 was fine, but 3 x 4096 > 8192
		{16, "", 65536},
		{5, `,"max_streams":64`, 8192},
		{2, `,"max_streams":10000`, 20000},
	} {
		body := `{"inbounds":[` + anyTLSIdentitiesJSON(tc.identities, tc.extra) + `]}`
		c, e := Load(writeConfig(t, body))
		if e != nil {
			t.Fatalf("%d identities%s rejected: %v", tc.identities, tc.extra, e)
		}
		if c.Limits.LogicalStreams != tc.want {
			t.Fatalf("%d identities%s: logical_streams %d, want %d", tc.identities, tc.extra, c.Limits.LogicalStreams, tc.want)
		}
		// Re-validation (as Start does) keeps the derived value and still treats it as automatic.
		if e := c.Validate(); e != nil || c.Limits.LogicalStreams != tc.want {
			t.Fatalf("re-validate: %v %d", e, c.Limits.LogicalStreams)
		}
	}
	// Mixed: one default identity plus the same identity on a second listener counts once.
	body := `{"inbounds":[` + anyTLSIdentitiesJSON(3, "") + `,{"protocol":"anytls","listen":"127.0.0.1:0","anytls":{"password":"identity-0"}}]}`
	c, e := Load(writeConfig(t, body))
	if e != nil || c.Limits.LogicalStreams != 12288 {
		t.Fatalf("shared identity counted twice: %v %d", e, c.Limits.LogicalStreams)
	}
	// Start uses the derived value for the global logical slot budget.
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	if s.logicalSlots.limit() != 12288 {
		t.Fatalf("runtime logical slots %d", s.logicalSlots.limit())
	}
}

func TestLogicalStreamsAutoRecomputedAfterIdentityChange(t *testing.T) {
	c, e := Load(writeConfig(t, `{"inbounds":[`+anyTLSIdentitiesJSON(1, "")+`]}`))
	if e != nil || c.Limits.LogicalStreams != 8192 {
		t.Fatal(e, c.Limits.LogicalStreams)
	}
	more, e := Load(writeConfig(t, `{"inbounds":[`+anyTLSIdentitiesJSON(3, "")+`]}`))
	if e != nil {
		t.Fatal(e)
	}
	c.Inbounds = more.Inbounds
	if e := c.Validate(); e != nil || c.Limits.LogicalStreams != 12288 {
		t.Fatalf("auto value not recomputed: %v %d", e, c.Limits.LogicalStreams)
	}
	// A value written after validation is explicit again and keeps the original constraint.
	c.Limits.LogicalStreams = 8192
	if e := c.Validate(); e == nil || !strings.Contains(e.Error(), "exceed logical_streams") {
		t.Fatalf("explicit logical_streams not enforced: %v", e)
	}
}

func TestLogicalStreamsExplicitKeepsConstraint(t *testing.T) {
	for _, tc := range []struct {
		limits, extra string
		identities    int
		ok            bool
	}{
		{`"logical_streams":256`, "", 1, false},                    // 4096 > 256
		{`"logical_streams":8192`, "", 3, false},                   // 12288 > 8192, never raised when written
		{`"logical_streams":12288`, "", 3, true},                   // exactly the sum
		{`"logical_streams":256`, `,"max_streams":64`, 4, true},    // 0.6.1 boundary: 256 <= 256
		{`"logical_streams":256`, `,"max_streams":64`, 5, false},   // 0.6.1 boundary: 320 > 256
		{`"logical_streams":4096`, `,"max_streams":4096`, 1, true}, // explicit 0.6.1 workaround
		{`"logical_streams":65537`, `,"max_streams":64`, 1, false}, // range unchanged
	} {
		body := `{"limits":{` + tc.limits + `},"inbounds":[` + anyTLSIdentitiesJSON(tc.identities, tc.extra) + `]}`
		c, e := Load(writeConfig(t, body))
		if (e == nil) != tc.ok {
			t.Fatalf("%s: %v", body, e)
		}
		if e == nil && fmt.Sprintf(`"logical_streams":%d`, c.Limits.LogicalStreams) != tc.limits {
			t.Fatalf("%s: explicit logical_streams changed to %d", body, c.Limits.LogicalStreams)
		}
		if e != nil && !tc.ok && !strings.Contains(e.Error(), "logical_streams") && !strings.Contains(e.Error(), "resource count") {
			t.Fatalf("%s: unexpected error %v", body, e)
		}
	}
}

func TestLogicalStreamsAutoStillBounded(t *testing.T) {
	// 17 default identities need 69632 workers: more than the 65536 hard maximum.
	_, e := Load(writeConfig(t, `{"inbounds":[`+anyTLSIdentitiesJSON(17, "")+`]}`))
	if e == nil || !strings.Contains(e.Error(), "65536 logical_streams maximum") {
		t.Fatalf("unbounded automatic logical_streams: %v", e)
	}
	// Explicit per-identity quotas make the same 17 identities valid again.
	c, e := Load(writeConfig(t, `{"inbounds":[`+anyTLSIdentitiesJSON(17, `,"max_streams":1024`)+`]}`))
	if e != nil || c.Limits.LogicalStreams != 17408 {
		t.Fatalf("explicit identity quotas: %v %d", e, c.Limits.LogicalStreams)
	}
}
