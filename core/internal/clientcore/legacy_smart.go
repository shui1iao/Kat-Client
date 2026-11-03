package clientcore

import (
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound/group"
)

var errLegacySmartSubscription = errors.New("Smart with subscription Model<2 is unsupported: ownership upgrade may restore snapshot credentials")

// Compatibility name; no migration, rendering, source writes or backup reads.
// Inspect declarations/ownership before the normal v1 upgrade can run.
func normalizeLegacySmartSource(text string, format DocumentFormat, projection []byte) (string, []byte, error) {
	var root map[string]json.RawMessage
	if e := json.Unmarshal(projection, &root); e != nil {
		return text, projection, e
	}
	smart := false
	groups := func(owner map[string]json.RawMessage) error {
		for _, b := range rawArray(owner, "groups") {
			var o group.Options
			if e := json.Unmarshal(b, &o); e != nil {
				return e
			}
			if o.Type == group.TypeSmart {
				smart = true
				if e := group.Validate(o); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if e := groups(rawObject(root["kernel"])); e != nil {
		return text, projection, e
	}
	var subs []map[string]json.RawMessage
	if e := json.Unmarshal(root["subscriptions"], &subs); len(root["subscriptions"]) > 0 && e != nil {
		return text, projection, e
	}
	legacy := false
	for _, s := range subs {
		var model int
		_ = json.Unmarshal(s["model"], &model)
		legacy = legacy || model < 2
		if e := groups(rawObject(s["snapshot"])); e != nil {
			return text, projection, e
		}
		// Patches/state may be partial; decode only the declared settings strictly.
		for _, owner := range []map[string]json.RawMessage{rawObject(rawObject(s["overlay"])["groups"]), rawObject(s["state"])} {
			for _, b := range owner {
				m := rawObject(b)
				var kind string
				_ = json.Unmarshal(m["type"], &kind)
				if kind == group.TypeSmart || m["smart"] != nil {
					smart = true
					v := rawJSON(map[string]any{"name": "validation", "type": "smart", "members": []string{"direct"}, "probe": map[string]any{"url": "http://127.0.0.1/"}})
					fields := rawObject(v)
					if m["smart"] != nil {
						fields["smart"] = m["smart"]
					}
					var o group.Options
					if e := json.Unmarshal(rawJSON(fields), &o); e != nil {
						return text, projection, e
					}
					if e := group.Validate(o); e != nil {
						return text, projection, e
					}
				}
			}
		}
	}
	if smart && legacy {
		return text, projection, errLegacySmartSubscription
	}
	return text, projection, nil
}
