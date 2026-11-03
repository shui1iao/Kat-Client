package clientcore

import (
	"encoding/json"
	"testing"
)

func TestK3GeneratedRuleDocumentApplyCapturesSubscriptionOverlay(t *testing.T) {
	for _, position := range []string{"top", "end"} {
		t.Run(position, func(t *testing.T) {
			h := fullHost(t)
			p := fullPreview(t, h, fullFixture, "")
			bAccept(t, h, p)
			bEdit(t, h, func(root map[string]json.RawMessage) {
				k := rawObject(root["kernel"])
				routing := rawObject(k["routing"])
				rules := rawArray(routing, "rules")
				routing["rules"] = rawJSON(append([]json.RawMessage{rawJSON(map[string]string{"domain": "manual.invalid", "action": "direct"})}, rules...))
				k["routing"] = rawJSON(routing)
				root["kernel"] = rawJSON(k)
			})
			before := bSubs(t, h)[0].Snapshot.Rules
			generated := rawJSON(map[string]string{"domain_suffix": "openai.com", "action": "direct"})
			v, e := h.selectSubscription(rawJSON(map[string]any{"id": p.ID, "add_rule": generated, "rule_position": position, "edit_only": true}))
			if e != nil {
				t.Fatal(e)
			}
			preview := v.(subscriptionPreview)
			bAccept(t, h, &preview)

			s := bSubs(t, h)[0]
			if len(s.Snapshot.Rules) != len(before) {
				t.Fatal("remote snapshot changed")
			}
			found := false
			for _, patch := range s.Overlay.Rules {
				if sameJSON(patch.Value, generated) && (position == "end" || patch.Position == 0) && len(patch.Original) == 0 {
					found = true
				}
			}
			if !found {
				t.Fatal("new first rule did not go through local overlay")
			}
			refresh := fullPreview(t, h, fullFixture, p.ID)
			bAccept(t, h, refresh)
			at := 0
			if position == "end" {
				at = len(h.doc.config.Routing.Rules) - 1
			}
			if h.doc.config.Routing.Rules[at].DomainSuffix != "openai.com" {
				t.Fatal("overlay position lost after subscription refresh")
			}
		})
	}
}
