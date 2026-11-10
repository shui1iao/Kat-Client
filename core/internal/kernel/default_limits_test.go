package kernel

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kat.json")
	if e := os.WriteFile(p, []byte(body), 0o600); e != nil {
		t.Fatal(e)
	}
	return p
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
