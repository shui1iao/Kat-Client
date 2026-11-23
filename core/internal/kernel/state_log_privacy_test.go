package kernel

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/stats"
)

func TestStatsLockFailureLogsNoWorkspacePath(t *testing.T) {
	dir := t.TempDir()
	busy := filepath.Join(dir, "runtime.stats.json")
	release, err := stats.Lock(busy)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	badParent := filepath.Join(dir, "not-a-dir")
	if err = os.WriteFile(badParent, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, reason string }{{busy, "file_in_use"}, {filepath.Join(badParent, "runtime.stats.json"), "lock_failed"}} {
		var lines []string
		k := &core{log: &logger{now: time.Now, clientSink: func(ClientLogEvent) {}, kernelSink: func(e KernelLogEvent) { lines = append(lines, e.Message) }}}
		k.openState(&Config{Stats: &StatsOptions{File: tc.path}})
		if len(lines) != 1 || lines[0] != "kat event=stats_persist_disabled reason="+tc.reason {
			t.Fatal("expected lock warning with finite reason and no path")
		}
	}
}
