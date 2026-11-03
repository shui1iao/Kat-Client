package clientcore

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPolicyDocumentIntervalProjection(t *testing.T) {
	h := fullHost(t)
	fixture := strings.Replace(fullFixture, "type: select", "type: url-test", 1)
	p := fullPreview(t, h, fixture, "")
	bAccept(t, h, p)
	seed, _ := sourceJSON(h.doc)
	for _, kind := range []string{"url-test", "smart", "fallback", "load-balance"} {
		for _, tc := range []struct {
			name, interval string
			want           time.Duration
		}{
			{"omitted", "", 0}, {"zero", "0s", 0}, {"explicit", "7m", 7 * time.Minute},
		} {
			for _, owned := range []bool{false, true} {
				t.Run(kind+"/"+tc.name+"/"+map[bool]string{false: "manual", true: "subscription"}[owned], func(t *testing.T) {
					root := rawObject(rawJSON(seed))
					k := rawObject(root["kernel"])
					gs := rawArray(k, "groups")
					g := rawObject(gs[0])
					g["type"] = rawJSON(kind)
					probe := rawObject(g["probe"])
					delete(probe, "interval")
					if tc.interval != "" {
						probe["interval"] = rawJSON(tc.interval)
					}
					g["probe"] = rawJSON(probe)
					if kind == "url-test" || kind == "smart" {
						g["tolerance"] = rawJSON(0)
						g["damping"] = rawJSON(map[string]any{"relative_improvement": 0, "min_dwell": "0s"})
					}
					gs[0] = rawJSON(g)
					k["groups"] = rawJSON(gs)
					root["kernel"] = rawJSON(k)
					if owned {
						subs, e := subscriptionsOf(seed)
						if e != nil {
							t.Fatal(e)
						}
						subs[0].Snapshot.Groups = gs
						root["subscriptions"] = rawJSON(subs)
					} else {
						delete(root, "subscriptions")
					}
					text := string(rawJSON(root))
					d, e := parseDocument(text, t.TempDir())
					if e != nil {
						t.Fatal(e)
					}
					want := tc.want
					if owned && want == 0 {
						want = 5 * time.Minute
						if kind == "url-test" {
							want = time.Minute
						}
					}
					if got := time.Duration(d.config.Groups[0].Probe.Interval); got != want {
						t.Fatal("runtime projection", got, want)
					}
					if d.text != text {
						t.Fatal("source bytes changed")
					}
					if kind == "url-test" || kind == "smart" {
						got := d.config.Groups[0]
						if !got.ToleranceSet || got.Tolerance != 0 || got.Damping.RelativeImprovement == nil || *got.Damping.RelativeImprovement != 0 || got.Damping.MinDwell == nil || *got.Damping.MinDwell != 0 {
							t.Fatal("explicit zero lost in client projection", got)
						}
					}
				})
			}
		}
	}
}

// Exercise the local-state capture, persistence and effective refresh path;
// dynamic names are never materialized into the hand-written member list.
func TestPolicySubscriptionDynamicWeightsSurviveRefresh(t *testing.T) {
	for _, kind := range []string{"url-test", "smart"} {
		for _, tc := range []struct {
			name, fields string
			dynamic      bool
		}{
			{"use", `"use":["p"]`, true},
			{"proxies", `"include_all_proxies":true`, true},
			{"providers", `"include_all_providers":true`, true},
			{"all", `"include_all":true`, true},
			{"source", `"include_group":"source"`, true},
			{"static", `"filter":"dyn"`, false},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				remote := rawJSON(map[string]any{"name": "g", "type": kind, "members": []string{"manual"}, "icon": "https://example.org/icon", "probe": map[string]any{"url": "https://example.org/probe", "interval": "7m"}})
				local := rawObject(remote)
				for key, val := range rawObject([]byte(`{` + tc.fields + `}`)) {
					local[key] = val
				}
				local["fixed"] = rawJSON("manual")
				local["filter"] = rawJSON("^(dyn|new)$")
				weights := map[string]float64{"manual": 2, "dyn": 1.5, "gone": .5}
				local["priority"] = rawJSON(weights)
				s := fullSubscription{Model: 2, Snapshot: fullSnapshot{Groups: []json.RawMessage{remote}}}
				kernel := map[string]json.RawMessage{
					"groups":    rawJSON([]json.RawMessage{rawJSON(local), rawJSON(map[string]any{"name": "source", "type": "select", "members": []string{"direct"}})}),
					"providers": rawJSON([]any{map[string]any{"name": "p"}}),
				}
				captureSubscriptionLocal(&s, kernel, nil)
				for gen, nodes := range [][]string{{"dyn"}, {"new"}, {"new", "dyn"}} {
					s.Snapshot.Outbounds = []json.RawMessage{rawJSON(map[string]any{"name": "manual", "type": "socks5"})}
					for _, n := range nodes {
						s.Snapshot.Outbounds = append(s.Snapshot.Outbounds, rawJSON(map[string]any{"name": n, "type": "socks5"}))
					}
					// A real on-disk round trip must preserve preference state too.
					b := rawJSON(s)
					if e := json.Unmarshal(b, &s); e != nil {
						t.Fatal(e)
					}
					effective := effectiveSubscription(&s, kernel)
					if len(s.Overlay.Invalid) != 0 {
						t.Fatal("local overlay rejected", s.Overlay.Invalid)
					}
					got := rawObject(effective.Groups[0])
					var actual map[string]float64
					if e := json.Unmarshal(got["priority"], &actual); e != nil {
						t.Fatal(e)
					}
					want := weights
					if !tc.dynamic {
						want = map[string]float64{"manual": 2}
					}
					if !reflect.DeepEqual(actual, want) {
						t.Fatalf("generation %d: weights %v, want %v", gen, actual, want)
					}
					if actual["new"] != 0 || string(got["members"]) != `["manual"]` || string(got["fixed"]) != `"manual"` || string(got["filter"]) != `"^(dyn|new)$"` || string(got["icon"]) != string(local["icon"]) || string(got["probe"]) != string(local["probe"]) {
						t.Fatal("unrelated fields changed or dynamic members/weights materialized", string(effective.Groups[0]))
					}
					for key, val := range rawObject([]byte(`{` + tc.fields + `}`)) {
						if key != "filter" && string(got[key]) != string(val) {
							t.Fatal("dynamic reference lost", key)
						}
					}
					// Capture the accepted projection again, as the next local edit
					// would; absent weights must survive this cycle, not just one merge.
					kernel["groups"] = rawJSON([]json.RawMessage{effective.Groups[0], rawJSON(map[string]any{"name": "source", "type": "select", "members": []string{"direct"}})})
					captureSubscriptionLocal(&s, kernel, nil)
				}
			})
		}
	}
}
