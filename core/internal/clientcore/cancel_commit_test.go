package clientcore

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Err is an observation point already required by the production path. This
// context injects cancellation at a named call site without adding production
// test hooks. In after mode the observed value precedes cancellation, modeling
// cancellation racing after that observation; predicate observation is
// not final rename admission because comparison can do blocking file I/O.
type boundaryContext struct {
	context.Context
	cancel       context.CancelFunc
	site         string
	hit, nth     int
	after, fired bool
}

func (c *boundaryContext) Err() error {
	if e := c.Context.Err(); e != nil {
		return e
	}
	pc := make([]uintptr, 16)
	n := runtime.Callers(2, pc)
	fs := runtime.CallersFrames(pc[:n])
	match := false
	// Only the immediate caller, not an ancestor, defines the checkpoint.
	f, _ := fs.Next()
	match = strings.HasSuffix(f.Function, c.site)
	if match {
		c.hit++
		if c.hit == c.nth {
			c.fired = true
			c.cancel()
			if c.after {
				return nil
			}
			return c.Context.Err()
		}
	}
	return nil
}
func TestApplyCancellationCommitBoundaries(t *testing.T) {
	for _, running := range []bool{false, true} {
		for _, converted := range []bool{false, true} {
			cases := []struct {
				site  string
				nth   int
				after bool
			}{
				{".applyContext", 2, false}, // transaction lock acquired, before parsing/save
			}
			if !running {
				site := ".saveDocumentContextLocked.func1"
				if converted {
					site = ".exclusiveDocumentWriteContext"
				}
				cases = append(cases, struct {
					site  string
					nth   int
					after bool
				}{site, 1, false}, struct {
					site  string
					nth   int
					after bool
				}{site, 1, true})
			} else {
				cases = append(cases, struct {
					site  string
					nth   int
					after bool
				}{".prepareContext", 4, false}, struct {
					site  string
					nth   int
					after bool
				}{".commitContext", 1, false}, struct {
					site  string
					nth   int
					after bool
				}{".commitContext", 1, true})
			}
			for _, tc := range cases {
				label := "stopped"
				if running {
					label = "running"
				}
				if converted {
					label += "-convert"
				}
				if tc.after {
					label += "-after"
				}
				t.Run(label+tc.site, func(t *testing.T) {
					h := newHost(t)
					text := fixture(t, map[string]any{"dns": map[string]any{"server": "system"}})
					if _, e := h.Apply(text); e != nil {
						t.Fatal(e)
					}
					if running {
						if _, e := h.Start(); e != nil {
							t.Fatal(e)
						}
					}
					beforePath, beforeText := h.path, h.doc.text
					gen := uint64(0)
					if running {
						gen = h.server.StatsView().Reload.Generation
					}
					sp := freePort(t)
					for sp == h.doc.client.HTTPPort || sp == h.doc.client.SOCKSPort {
						sp = freePort(t)
					}
					var doc map[string]any
					json.Unmarshal([]byte(text), &doc)
					doc["client"].(map[string]any)["socks_port"] = sp
					raw, _ := json.Marshal(doc)
					draft := string(raw)
					format := FormatJSON
					if converted {
						format = FormatYAML
						draft = yamlFixture(h.doc.client.HTTPPort, sp) + "# exact comment retained\n"
					}
					parent, cancel := context.WithCancel(context.Background())
					defer cancel()
					ctx := &boundaryContext{Context: parent, cancel: cancel, site: tc.site, nth: tc.nth, after: tc.after}
					result, e := h.applyContext(ctx, draft, format)
					if !ctx.fired {
						t.Fatal("boundary injection did not execute")
					}
					// Cancellation after the predicate's first ctx read
					// is still pre-admission: the final rename check must
					// reject it. Link/kernel retain their existing boundary.
					accepted := tc.after && (running || converted)
					if !accepted {
						if e == nil || e.Code != "request_canceled" || e.Message != "请求已取消，未接纳更改" {
							t.Fatal("precommit cancellation not safely reported", e)
						}
						b, err := os.ReadFile(beforePath)
						if err != nil || string(b) != beforeText || h.path != beforePath || h.doc.text != beforeText {
							t.Fatal("cancellation changed accepted source")
						}
						if running && h.server.StatsView().Reload.Generation != gen {
							t.Fatal("cancellation changed running generation")
						}
						// Any newly prepared SOCKS listener was released.
						l, err := net.Listen("tcp4", portAddress(sp))
						if err != nil {
							t.Fatal("canceled candidate leaked listener")
						}
						l.Close()
					} else {
						if e != nil || result == nil || h.doc.text != draft || h.doc.format != format {
							t.Fatal("late cancellation falsely undid committed change", e)
						}
						b, err := os.ReadFile(h.path)
						if err != nil || string(b) != draft {
							t.Fatal("committed source not accepted")
						}
						if running && h.server.StatsView().Reload.Generation != gen+1 {
							t.Fatal("committed generation not acknowledged")
						}
					}
					left, _ := filepath.Glob(filepath.Join(h.workspace, ".kat-*"))
					if len(left) != 0 {
						t.Fatal("transaction material leaked")
					}
					t.Logf("running=%v conversion=%v checkpoint=%s after=%v old-preserved=%v", running, converted, tc.site, tc.after, !accepted)
				})
			}
		}
	}
}
func TestCanceledApplyQueuedOnTransactionLock(t *testing.T) {
	h := newHost(t)
	before := h.doc.text
	draft := fixture(t, map[string]any{})
	h.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	done := make(chan *Error, 1)
	go func() { defer wg.Done(); _, e := h.applyContext(ctx, draft); done <- e }()
	cancel()
	h.mu.Unlock()
	wg.Wait()
	if e := <-done; e == nil || e.Code != "request_canceled" {
		t.Fatal("queued cancel not honored")
	}
	if b, e := os.ReadFile(h.path); e != nil || string(b) != before {
		t.Fatal("queued cancellation published")
	}
}
func TestIPCMethodBudgets(t *testing.T) {
	for _, method := range []string{"probe.node", "probe.group", "probe.all"} {
		if requestBudget(method) != 305*time.Second {
			t.Fatal("slow ceiling")
		}
	}
	for _, method := range []string{"hello", "import.parse", "document.apply", "document.validate", "core.stop", "status", "unknown"} {
		if requestBudget(method) != 35*time.Second {
			t.Fatal("ordinary ceiling")
		}
	}
}
