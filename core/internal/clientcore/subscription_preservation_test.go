package clientcore

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// A rule snapshot proves ownership only when it has one possible position.
// A manual block or another subscription may legally contain identical rules.
func TestFullSubscriptionAmbiguousRuleBlockPreserves(t *testing.T) {
	const original = "proxies: []\nrules: ['DOMAIN,example.invalid,DIRECT']\n"
	changed := strings.Replace(original, "example.invalid,DIRECT", "example.invalid,REJECT", 1)
	for _, neighbor := range []string{"manual", "subscription"} {
		t.Run(neighbor, func(t *testing.T) {
			h := fullHost(t)
			if neighbor == "manual" {
				text := strings.Replace(initialDocument, `"kernel":{}`, `"kernel":{"routing":{"rules":[{"domain":"example.invalid","action":"direct"}],"final":"direct"}}`, 1)
				if _, e := h.Apply(text); e != nil {
					t.Fatal(e)
				}
			}
			p := fullPreview(t, h, original, "")
			if _, e := h.Apply(p.Text); e != nil {
				t.Fatal(e)
			}
			if neighbor == "subscription" {
				q := fullPreview(t, h, original, "")
				if _, e := h.Apply(q.Text); e != nil {
					t.Fatal(e)
				}
			}
			before := h.doc.text
			disk, e := os.ReadFile(h.path)
			if e != nil {
				t.Fatal(e)
			}
			root, _ := sourceJSON(h.doc)
			owner := string(root["subscriptions"])
			var k, r map[string]json.RawMessage
			_ = json.Unmarshal(root["kernel"], &k)
			_ = json.Unmarshal(k["routing"], &r)
			priorRules := rawArray(r, "rules")
			if neighbor == "subscription" {
				if len(priorRules) != 1 {
					t.Fatal("inactive subscription participated in runtime")
				}
				q := fullPreview(t, h, changed, p.ID)
				if _, e := h.Apply(q.Text); e != nil {
					t.Fatal(e)
				}
				return
			}
			if len(priorRules) != 2 || !sameJSON(priorRules[0], priorRules[1]) {
				t.Fatal("repro must contain two identical legal rule blocks")
			}
			for _, text := range []string{changed, original} {
				_, err := h.previewSubscription(context.Background(), rawJSON(map[string]string{"text": text, "id": p.ID}))
				if err == nil || err.Code != "subscription_conflict" || err.Path != "rules" {
					t.Fatal("ambiguous ownership must refuse instead of replacing the first equal rule block")
				}
				if h.doc.text != before || h.fullPending != nil {
					t.Fatal("ambiguous refresh modified accepted state or staged a commit")
				}
				after, e := os.ReadFile(h.path)
				if e != nil || string(after) != string(disk) {
					t.Fatal("ambiguous refresh changed source bytes")
				}
				root, _ := sourceJSON(h.doc)
				if string(root["subscriptions"]) != owner {
					t.Fatal("ambiguous refresh changed ownership")
				}
				_ = json.Unmarshal(root["kernel"], &k)
				_ = json.Unmarshal(k["routing"], &r)
				if !sameJSON(r["rules"], rawJSON(priorRules)) {
					t.Fatal("manual/other-subscription rule order changed")
				}
			}
		})
	}
}
