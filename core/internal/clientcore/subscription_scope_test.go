package clientcore

import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/provider"
	"net/http"
	"strings"
	"testing"
)

func TestSubscriptionAuthRequestRoles(t *testing.T) {
	h := fullHost(t)
	cfg := kernel.ProviderConfig{URL: "https://primary.invalid/start", Headers: map[string]string{"X-Provider-Auth": "test-only"}, UserAgent: "provider-fixture"}
	ctx := context.WithValue(context.Background(), legacyKey{}, &legacyConversion{Config: cfg})
	var want bool
	h.fullFetch = func(c context.Context, u string, _ *clientegress.Policy, _ int64) ([]byte, error) {
		req, _ := http.NewRequestWithContext(c, "GET", u, nil)
		setSubscriptionRequestHeaders(req)
		if (req.Header.Get("X-Provider-Auth") != "") != want || (req.UserAgent() == cfg.UserAgent) != want {
			t.Fatal("wrong credential scope")
		}
		return []byte("fixture"), nil
	}
	for _, tc := range []struct {
		u          string
		main, auth bool
	}{{"https://PRIMARY.invalid:443/main", true, true}, {"https://primary.invalid:8443/main", true, false}, {"https://other.invalid/main", true, false}, {"https://primary.invalid/dep", false, false}, {"https://other.invalid/dep", false, false}} {
		want = tc.auth
		if tc.main {
			_, _, e := h.fetchMainSubscription(ctx, tc.u, nil, 100, "direct", "", nil)
			if e != nil {
				t.Fatal(e)
			}
		} else {
			_, e := h.fetchSubscriptionResource(ctx, tc.u, nil, 100)
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	from, _ := http.NewRequest("GET", cfg.URL, nil)
	other, _ := http.NewRequest("GET", "https://other.invalid/first", nil)
	for _, tc := range []struct {
		u                  string
		main, want, bounce bool
	}{{"https://primary.invalid:443/path", true, true, false}, {"https://other.invalid/file", true, false, false}, {"https://primary.invalid/back", true, false, true}, {"https://primary.invalid/dep", false, false, false}} {
		c := context.WithValue(ctx, mainSubscriptionRequestKey{}, tc.main)
		req, _ := http.NewRequestWithContext(c, "GET", tc.u, nil)
		req.Header.Set("X-Provider-Auth", "auto-copied")
		chain := []*http.Request{from}
		if tc.bounce {
			chain = append(chain, other)
		}
		if e := subscriptionRedirect(req, chain); e != nil || (req.Header.Get("X-Provider-Auth") != "") != tc.want {
			t.Fatal("redirect credential scope", tc.u, e)
		}
	}
}

func TestSubscriptionTextAcceptedWithProbeProvenance(t *testing.T) {
	h := fullHost(t)
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return []byte(".child.test\n+.suffix.test"), nil
	}
	s := strings.Replace(fullFixture, "type: select", "type: url-test, url: https://probe.invalid/status", 1) + "rule-providers:\n  sample: {type: http, format: text, behavior: domain, url: https://rules.invalid/text}\n"
	p := fullPreview(t, h, s, "")
	bAccept(t, h, p)
	if len(h.doc.config.RuleSets) != 1 || h.doc.config.RuleSets[0].Format != "mihomo-text" || !h.doc.config.Groups[0].Probe.PublicDirectOnly {
		t.Fatal("accepted text/probe projection lost")
	}
	bEdit(t, h, func(root map[string]json.RawMessage) {
		k := rawObject(root["kernel"])
		groups := rawArray(k, "groups")
		g := rawObject(groups[0])
		pr := rawObject(g["probe"])
		pr["url"] = rawJSON("http://operator.invalid/health")
		g["probe"] = rawJSON(pr)
		groups[0] = rawJSON(g)
		k["groups"] = rawJSON(groups)
		root["kernel"] = rawJSON(k)
	})
	if h.doc.config.Groups[0].Probe.URL != "http://operator.invalid/health" || h.doc.config.Groups[0].Probe.PublicDirectOnly {
		t.Fatal("operator URL override lost")
	}
}
func TestSubscriptionImportReplyCounts(t *testing.T) {
	h := fullHost(t)
	n := provider.MaxSkippedDetails + 3
	v, e := h.importParse(context.Background(), rawJSON(map[string]string{"text": strings.Repeat("unsupported://record\n", n)}))
	if e != nil {
		t.Fatal(e)
	}
	r := v.(map[string]any)
	if r["skipped_total"] != n || len(r["skipped"].([]any)) != provider.MaxSkippedDetails {
		t.Fatal("summary did not survive import")
	}
}
func TestSubscriptionMigrationPinRefusal(t *testing.T) {
	_, e := legacyFull([]byte(`{"outbounds":[{"type":"trojan","tag":"fixture","tls":{"enabled":true,"certificate_public_key_sha256":["test-only"]}}]}`), "", &legacyConversion{})
	fe, ok := e.(*provider.FullError)
	if !ok || fe.Code != "unsupported_spki_pin" {
		t.Fatal("migration must retain provider rather than accept empty policy", e)
	}
}
