package clientcore

import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/clientdiag"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestRound5LegacyCacheFiltersRemovedServicesReadOnly(t *testing.T) {
	for _, memory := range []bool{false, true} {
		t.Run(map[bool]string{false: "disk", true: "memory"}[memory], func(t *testing.T) {
			h := newHost(t)
			r := &diagnosticReply{At: time.Now().UTC().Truncate(time.Second), Items: []diagnosticRow{}}
			for _, name := range append(append([]string{}, clientdiag.Services...), "TikTok", "YouTube", "YouTube Premium", "Claude", "Disney+") {
				r.Items = append(r.Items, diagnosticRow{Name: name, Verdict: clientdiag.Verdict{Result: "failed", Reason: "previous-reason"}, Chain: []string{"Final", "Node"}})
			}
			beforeRows := append([]diagnosticRow{}, r.Items...)
			if err := h.saveDiagnosticCache("unlock", r); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(h.workspace, "network-diagnostic-unlock.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if memory {
				h.diagCache = map[string]*diagnosticReply{"unlock": r}
			}
			for range 2 {
				value, e := h.diagnosticsNetwork(context.Background(), json.RawMessage(`{"kind":"unlock","run":false}`))
				if e != nil {
					t.Fatal(e)
				}
				got := value.(*diagnosticReply)
				if !got.At.Equal(r.At) || !reflect.DeepEqual(got.Items, beforeRows[:len(clientdiag.Services)]) {
					t.Fatal("lost unrelated cache fields", got)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil || string(before) != string(after) || h.server != nil || !reflect.DeepEqual(r.Items, beforeRows) {
				t.Fatal("cache read mutated history or started kernel", err)
			}
			if visibleDiagnosticCache("connectivity", r) != r || visibleDiagnosticCache("exit", r) != r {
				t.Fatal("changed other kinds")
			}
		})
	}
}
