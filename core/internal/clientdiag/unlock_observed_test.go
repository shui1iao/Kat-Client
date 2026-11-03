package clientdiag

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real response SHA: 492f48831d0c0dd723a1f3f13081894a8ea4bea307f482f421a50e498c752b9f.
// Only the official public policy field is retained here. Auxiliary trace below
// is synthetic regression data, NOT a claim about the uncollected Bero trace.
func TestAnonymousObservedComplianceField(t *testing.T) {
	for _, c := range []struct {
		body, want string
		calls      int
	}{
		{`{"cookie_consent_required":false}`, "unlocked", 2},
		{`{"cookie_consent_required":true}`, "unlocked", 2},
		{`{"cookie_consent_required":false,"requires_cookie_consent":false}`, "unlocked", 2},
		{`{"cookie_consent_required":false,"requires_cookie_consent":true}`, "unknown", 1},
		{`{"cookie_consent_required":"invalid"}`, "unknown", 1},
		{`{"cookie_consent_required":null}`, "unknown", 1},
		{`{"cookie_consent_required":false,"error":{"code":"unknown"}}`, "unknown", 1},
	} {
		calls := 0
		v := Detect(context.Background(), "ChatGPT", func(_ context.Context, m, u string) (Page, error) {
			calls++
			if m != "GET" {
				t.Fatal("wrong method")
			}
			if calls == 1 {
				return Page{Status: 200, Body: c.body}, nil
			}
			if u != "https://chat.openai.com/cdn-cgi/trace" {
				t.Fatal("wrong auxiliary endpoint")
			}
			return Page{Status: 200, Body: "ip=203.0.113.9\nloc=SG\n"}, nil
		})
		if v.Result != c.want || calls != c.calls {
			t.Fatal("policy regression", v, calls)
		}
	}
}

// Optional PRIVATE original-body replay. No HTTP client, no network and no
// copied raw body in git. The capture directory is supplied only by the owner.
func TestAnonymousCapturedBeroResponses(t *testing.T) {
	dir := os.Getenv("KAT_UNLOCK_CAPTURE_DIR")
	if dir == "" {
		t.Skip("requires authorized private original response directory")
	}
	for _, c := range []struct {
		id, service, sha, want string
		bytes                  int
	}{
		{"chatgpt", "ChatGPT", "492f48831d0c0dd723a1f3f13081894a8ea4bea307f482f421a50e498c752b9f", "followup_required", 38},
	} {
		t.Run(c.id, func(t *testing.T) {
			b, e := os.ReadFile(filepath.Join(dir, c.id+".body"))
			if e != nil {
				t.Fatal("private body unavailable")
			}
			h := sha256.Sum256(b)
			if len(b) != c.bytes || hex.EncodeToString(h[:]) != c.sha {
				t.Fatal("private body identity mismatch")
			}
			m, e := os.ReadFile(filepath.Join(dir, c.id+".json"))
			if e != nil {
				t.Fatal("private metadata unavailable")
			}
			var meta struct {
				Status   int    `json:"http_status"`
				Host     string `json:"final_host"`
				Path     string `json:"final_path_category"`
				Complete bool   `json:"capture_complete"`
				Route    bool   `json:"route_observed"`
			}
			if json.Unmarshal(m, &meta) != nil || !meta.Complete || meta.Route {
				t.Fatal("capture contract mismatch")
			}
			path := "/"
			if meta.Path == "about" {
				path = "/about"
			}
			calls := 0
			v := Detect(context.Background(), c.service, func(_ context.Context, method, u string) (Page, error) {
				calls++
				if calls > 1 {
					if c.id != "chatgpt" || u != "https://chat.openai.com/cdn-cgi/trace" {
						t.Fatal("unexpected uncaptured endpoint")
					}
					return Page{}, errors.New("auxiliary response was not captured")
				}
				return Page{Status: meta.Status, Body: string(b), URL: "https://" + meta.Host + path}, nil
			})
			if c.id == "chatgpt" {
				// Do NOT interpret injected follow-up absence as a live failure.
				if calls != 2 || !strings.Contains(v.Reason, "辅助地区 trace") {
					t.Fatal("actual policy did not reach required auxiliary stage", v)
				}
				t.Log("actual_policy_accepted=true auxiliary_trace_not_captured=true final_live_verdict=not_evaluated")
			} else {
				if calls != 1 || v.Result != c.want {
					t.Fatal("actual body regression", v)
				}
				t.Logf("actual_body_replay=%s http=%d route_observed=false not_new_network_verification=true", v.Result, meta.Status)
			}
		})
	}
}
