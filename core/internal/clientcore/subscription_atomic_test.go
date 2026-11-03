package clientcore

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/clientegress"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFullSubscriptionResourceAtomicFailureAndCancel(t *testing.T) {
	h := fullHost(t)
	fixture := strings.Replace(fullFixture, "rules:\n", `rule-providers:
  external: {type: http, behavior: classical, format: yaml, url: https://rules.example.invalid/set, path: ../../escape.yaml, interval: 86400}
rules:
  - RULE-SET,external,pick
`, 1)
	content := []byte("payload: ['DOMAIN,controlled.invalid']\n")
	broken := false
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		if broken {
			return nil, errors.New("must remain private")
		}
		return content, nil
	}
	p := fullPreview(t, h, fixture, "")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	before := h.doc.text
	set := h.doc.config.RuleSets[0]
	if set.URL != "" || set.Interval != 0 || !strings.HasPrefix(set.Path, h.workspace+string(filepath.Separator)) {
		t.Fatal("resource not private immutable full-snapshot cache")
	}
	prior, e := os.ReadFile(set.Path)
	if e != nil {
		t.Fatal(e)
	}
	broken = true
	missingFixture := strings.Replace(fixture, "https://rules.example.invalid/set", "https://rules.example.invalid/set/missing", 1)
	_, err := h.previewSubscription(context.Background(), rawJSON(map[string]string{"text": missingFixture, "id": p.ID}))
	if err == nil || h.doc.text != before {
		t.Fatal("resource failure changed accepted config")
	}
	after, e := os.ReadFile(set.Path)
	if e != nil || string(prior) != string(after) {
		t.Fatal("old cache changed")
	}
	broken = false
	content = []byte("payload: ['DOMAIN,new.invalid']")
	q := fullPreview(t, h, missingFixture, p.ID)
	dir := h.fullPending.Dir
	if _, err := h.cancelSubscription(rawJSON(map[string]string{"token": q.Token})); err != nil {
		t.Fatal(err)
	}
	if _, e := os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("canceled stage remains")
	}
	if h.doc.text != before {
		t.Fatal("cancel committed")
	}
	after, e = os.ReadFile(set.Path)
	if e != nil || string(after) != string(prior) {
		t.Fatal("cancel removed accepted cache")
	}
	content = []byte("payload: ['PROCESS-UNSUPPORTED,x']\n")
	v, err := h.previewSubscription(context.Background(), rawJSON(map[string]string{"text": missingFixture, "id": p.ID}))
	if err != nil || len(v.(subscriptionPreview).Issues) == 0 || h.doc.text != before {
		t.Fatal("unsupported condition silently accepted")
	}
	if !strings.Contains(v.(subscriptionPreview).Issues[0], "payload第1条") {
		t.Fatal("structured invalid entry position lost")
	}

}
func TestFullSubscriptionUnknownViaCannotDisappear(t *testing.T) {
	h := fullHost(t)
	fixture := strings.Replace(fullFixture, "server: example.org", "dialer-proxy: unknown-external, server: example.org", 1)
	v, e := h.previewSubscription(context.Background(), rawJSON(map[string]string{"text": fixture}))
	if e != nil {
		t.Fatal(e)
	}
	if len(v.(subscriptionPreview).Issues) == 0 {
		t.Fatal("unknown Via silently became default direct")
	}
}
