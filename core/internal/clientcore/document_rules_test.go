package clientcore

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestC15SniffOptionalProjectionAndFormats(t *testing.T) {
	for _, tc := range []struct {
		name, extra, tcp, udp string
		timeout               time.Duration
	}{
		{"legacy", "", "80,443,8080,8443", "443", 300 * time.Millisecond},
		{"custom", `,"tcp_ports":"80,443,8000-8100","udp_ports":"none","timeout":"1.5s"`, "80,443,8000-8100", "none", 1500 * time.Millisecond},
		{"both-none", `,"tcp_ports":"none","udp_ports":"none","timeout":"1ms"`, "none", "none", time.Millisecond},
		{"slash-and-max", `,"tcp_ports":"80/443","udp_ports":"443-444","timeout":"2s"`, "80/443", "443-444", 2 * time.Second},
		{"explicit-default", `,"tcp_ports":"","udp_ports":"","timeout":"0s"`, "80,443,8080,8443", "443", 300 * time.Millisecond},
	} {
		for _, enabled := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{true: "-on", false: "-off"}[enabled], func(t *testing.T) {
				h := newHost(t)
				old := fixture(t, map[string]any{})
				flag := "false"
				if enabled {
					flag = "true"
				}
				text := strings.Replace(old, `"client":{`, `"client":{ "sniff":{ "enabled":`+flag+`,"override_destination":true`+tc.extra+` },`, 1)
				if _, e := applyLegacyFixture(h, text); e != nil {
					t.Fatal(e)
				}
				if h.doc.text != text {
					t.Fatal("source bytes changed")
				}
				in := h.doc.config.Inbounds[0].Sniff
				if !enabled {
					if in != nil {
						t.Fatal("disabled sniff became active")
					}
				} else if in == nil || in.TCPPorts != tc.tcp || in.UDPPorts != tc.udp || in.Timeout != kernel.Duration(tc.timeout) || !in.OverrideDestination {
					t.Fatalf("bad projection %+v", in)
				}
				var source any
				if e := json.Unmarshal([]byte(text), &source); e != nil {
					t.Fatal(e)
				}
				y, e := yaml.Marshal(source)
				if e != nil {
					t.Fatal(e)
				}
				y = append([]byte("# sniff optional fields retained\n"), y...)
				if _, e := applyLegacyFixture(h, string(y), FormatYAML); e != nil || h.doc.text != string(y) {
					t.Fatal("YAML bytes changed", e)
				}
				b, e := yamlJSON(y)
				if e != nil {
					t.Fatal(e)
				}
				if _, e := applyLegacyFixture(h, string(b), FormatJSON); e != nil {
					t.Fatal(e)
				}
				var a, bj map[string]any
				_ = json.Unmarshal([]byte(text), &a)
				_ = json.Unmarshal(b, &bj)
				aj, _ := json.Marshal(a["client"])
				bjraw, _ := json.Marshal(bj["client"])
				if string(aj) != string(bjraw) {
					t.Fatal("format conversion lost fields")
				}
			})
		}
	}
}
func TestC15SniffErrorsAreFieldScopedAndAtomic(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"tcp_ports", `42`}, {"udp_ports", `null`}, {"timeout", `300`}, {"tcp_ports", `"65536"`}, {"udp_ports", `"443,"`}, {"tcp_ports", `"8100-8000"`}, {"udp_ports", `"NONE"`}, {"timeout", `""`}, {"timeout", `"0.5ms"`}, {"timeout", `"2001ms"`}, {"timeout", `"-1ms"`}, {"timeout", `null`}, {"unknown", `"anything"`},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			h := newHost(t)
			old := fixture(t, map[string]any{})
			if _, e := applyLegacyFixture(h, old); e != nil {
				t.Fatal(e)
			}
			for _, flag := range []string{"false", "true"} {
				block := `{"enabled":` + flag + `,"override_destination":false,"` + tc.key + `":` + tc.value + `}`
				// Validate the exact same paths used by document.validate before document.apply.
				e := validateSniff([]byte(`{"sniff":` + block + `}`))
				if e == nil || e.Path != "client.sniff."+tc.key {
					t.Fatalf("wrong field: %+v", e)
				}
				text := strings.Replace(old, `"client":{`, `"client":{"sniff":`+block+`,`, 1)
				if _, e := applyLegacyFixture(h, text); e == nil || h.doc.text != old {
					t.Fatal("invalid field saved or changed accepted bytes")
				}
			}
		})
	}
}

func TestSniffSkipDomainProjectionAndValidation(t *testing.T) {
	h := newHost(t)
	old := fixture(t, map[string]any{})
	if _, e := applyLegacyFixture(h, old); e != nil {
		t.Fatal(e)
	}
	// Default omitted skip_domain keeps SkipDomain == nil on SniffOptions.
	if h.doc.config.Inbounds[0].Sniff == nil || h.doc.config.Inbounds[0].Sniff.SkipDomain != nil {
		t.Fatalf("expected nil SkipDomain when omitted, got %+v", h.doc.config.Inbounds[0].Sniff)
	}
	// Explicit empty skip_domain: [] is preserved as non-nil empty slice.
	emptyText := strings.Replace(old, `"client":{`, `"client":{"sniff":{"enabled":true,"override_destination":true,"skip_domain":[]},`, 1)
	if _, e := applyLegacyFixture(h, emptyText); e != nil {
		t.Fatal(e)
	}
	if h.doc.config.Inbounds[0].Sniff.SkipDomain == nil || len(h.doc.config.Inbounds[0].Sniff.SkipDomain) != 0 {
		t.Fatalf("expected non-nil empty SkipDomain, got %#v", h.doc.config.Inbounds[0].Sniff.SkipDomain)
	}
	// Custom skip_domain entries roundtrip and project cleanly.
	customText := strings.Replace(old, `"client":{`, `"client":{"sniff":{"enabled":true,"override_destination":true,"skip_domain":["+.push.apple.com","Mijia Cloud"]},`, 1)
	if _, e := applyLegacyFixture(h, customText); e != nil {
		t.Fatal(e)
	}
	if len(h.doc.config.Inbounds[0].Sniff.SkipDomain) != 2 {
		t.Fatalf("unexpected SkipDomain: %#v", h.doc.config.Inbounds[0].Sniff.SkipDomain)
	}
	// Invalid skip_domain values fail with path client.sniff.skip_domain.
	tooMany := make([]string, 129)
	for i := range tooMany {
		tooMany[i] = `"+.a.example"`
	}
	for _, bad := range []string{
		`null`,
		`"string"`,
		`123`,
		`[null]`,
		`[""]`,
		`["   "]`,
		`["+."]`,
		`["+..."]`,
		`["*..."]`,
		`["..."]`,
		`["+. ."]`,
		`["+.a..b"]`,
		`["bad\u0007ctrl"]`,
		`["` + strings.Repeat("a", 254) + `"]`,
		`[` + strings.Join(tooMany, ",") + `]`,
	} {
		e := validateSniff([]byte(`{"sniff":{"enabled":true,"override_destination":true,"skip_domain":` + bad + `}}`))
		if e == nil || e.Path != "client.sniff.skip_domain" {
			t.Fatalf("bad=%s expected client.sniff.skip_domain error, got %+v", bad, e)
		}
	}

	// Disabled sniff preserves full configuration fields in JSON/YAML document & ClientSniff MarshalJSON while keeping runtime sniffing inactive.
	disabledSkipText := strings.Replace(old, `"client":{`, `"client":{"sniff":{"enabled":false,"override_destination":true,"tcp_ports":"80,443","udp_ports":"443","timeout":"400ms","skip_domain":["+.push.apple.com","Mijia Cloud"]},`, 1)
	if _, e := applyLegacyFixture(h, disabledSkipText); e != nil {
		t.Fatal(e)
	}
	if h.doc.config.Inbounds[0].Sniff != nil {
		t.Fatalf("expected runtime Inbounds[0].Sniff == nil when enabled=false, got %+v", h.doc.config.Inbounds[0].Sniff)
	}
	rawClientSniff, err := json.Marshal(ClientSniff{
		Enabled:             false,
		OverrideDestination: false,
		TCPPorts:            "80,443",
		UDPPorts:            "443",
		Timeout:             "400ms",
		SkipDomain:          []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip map[string]any
	if err := json.Unmarshal(rawClientSniff, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if roundtrip["enabled"] != false || roundtrip["override_destination"] != false {
		t.Fatalf("ClientSniff MarshalJSON lost false booleans: %s", string(rawClientSniff))
	}
	if sk, ok := roundtrip["skip_domain"].([]any); !ok || len(sk) != 0 {
		t.Fatalf("ClientSniff MarshalJSON lost empty skip_domain=[]: %s", string(rawClientSniff))
	}
}

func TestK1ManualSwitchClosesOnlyNestedGroupOldTCP(t *testing.T) {
	for _, action := range []string{"select", "pin", "unpin"} {
		for _, enabled := range []bool{true, false} {
			t.Run(action+"/"+strconv.FormatBool(enabled), func(t *testing.T) {
				ln, e := net.Listen("tcp4", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer ln.Close()
				go func() {
					for {
						c, e := ln.Accept()
						if e != nil {
							return
						}
						go func() { defer c.Close(); io.Copy(c, c) }()
					}
				}()
				h := newHost(t)
				k := map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}, "groups": []any{
					map[string]any{"name": "Child", "type": "select", "members": []string{"direct"}},
					map[string]any{"name": "Final", "type": "select", "members": []string{"Child", "direct"}, "selected": "Child"},
					map[string]any{"name": "Emby", "type": "select", "members": []string{"direct"}},
				}, "routing": map[string]any{"rules": []any{map[string]any{"domain": "localhost", "outbound": "Final"}}, "final": "Emby"}}
				if action != "select" {
					child := k["groups"].([]any)[0].(map[string]any)
					child["type"] = "fallback"
					child["probe"] = map[string]any{"url": "http://127.0.0.1:1/"}
					if action == "unpin" {
						child["fixed"] = "direct"
					}
				}
				text := fixture(t, k)
				if !enabled {
					text = settingsText(t, text, map[string]any{"close_on_switch": false})
				}
				if _, e := h.Apply(text); e != nil {
					t.Fatal(e)
				}
				if _, e := h.Start(); e != nil {
					t.Fatal(e)
				}
				d, e := proxy.SOCKS5("tcp", portAddress(h.doc.client.SOCKSPort), nil, proxy.Direct)
				if e != nil {
					t.Fatal(e)
				}
				_, port, _ := net.SplitHostPort(ln.Addr().String())
				a, e := d.Dial("tcp", net.JoinHostPort("localhost", port))
				if e != nil {
					t.Fatal(e)
				}
				defer a.Close()
				other, e := d.Dial("tcp", ln.Addr().String())
				if e != nil {
					t.Fatal(e)
				}
				defer other.Close()
				echo := func(c net.Conn) error {
					c.SetDeadline(time.Now().Add(time.Second))
					if _, e := c.Write([]byte("x")); e != nil {
						return e
					}
					_, e := io.ReadFull(c, make([]byte, 1))
					return e
				}
				if e := echo(a); e != nil {
					t.Fatal(e)
				}
				if e := echo(other); e != nil {
					t.Fatal(e)
				}
				// Changing the nested Child selection must match Final -> Child -> direct.
				var root map[string]any
				_ = json.Unmarshal([]byte(h.doc.text), &root)
				child := root["kernel"].(map[string]any)["groups"].([]any)[0].(map[string]any)
				switch action {
				case "select":
					child["selected"] = "direct"
				case "pin":
					child["fixed"] = "direct"
				case "unpin":
					delete(child, "fixed")
				}
				gen := h.server.GenerationID()
				next, _ := json.Marshal(root)
				if _, e := h.Apply(string(next)); e != nil {
					t.Fatal(e)
				}
				if h.server.GenerationID() != gen {
					t.Fatal("manual selection rebuilt generation")
				}
				e = echo(a)
				if enabled && e == nil {
					t.Fatal("selected group's old flow survived")
				}
				if !enabled && e != nil {
					t.Fatal("disabled close-on-switch killed old flow", e)
				}
				if e := echo(other); e != nil {
					t.Fatal("unrelated Emby flow closed", e)
				}
			})
		}
	}
}
func TestK1SourceFidelityDefaultsAndValidation(t *testing.T) {
	h := newHost(t)
	for _, f := range []DocumentFormat{FormatJSON, FormatYAML} {
		text := fixture(t, map[string]any{"groups": []any{map[string]any{"name": "S", "type": "smart", "members": []string{"direct"}, "probe": map[string]any{"url": "http://127.0.0.1:1/"}, "tolerance": 0, "damping": map[string]any{"relative_improvement": 0, "confirm_rounds": 2, "min_dwell": "0s"}, "smart": map[string]any{"scope": "group", "exploration_rate": .02}}}})
		if f == FormatYAML {
			text = "# K1 source comment\n" + yamlFixture(h.doc.client.HTTPPort, h.doc.client.SOCKSPort) + "  groups:\n    - name: S\n      type: smart\n      members: [direct]\n      probe: {url: http://127.0.0.1:1/}\n      tolerance: 0\n      smart: {scope: site}\n"
		}
		d, e := parseDocument(text, h.workspace, f)
		if e != nil {
			t.Fatal(e)
		}
		if d.text != text {
			t.Fatal("source rewritten")
		}
		if !d.config.Groups[0].ToleranceSet || d.config.Groups[0].Tolerance != 0 {
			t.Fatal("explicit numeric zero lost")
		}
	}
	text := settingsText(t, initialDocument, map[string]any{"close_on_switch": nil})
	if _, e := parseDocument(text, h.workspace); e == nil {
		t.Fatal("null switch accepted")
	}
}
func TestK1SubscriptionOverlayKeepsSmartAndDamping(t *testing.T) {
	h := fullHost(t)
	const remote = "proxies: [{name: n, type: socks5, server: 127.0.0.1, port: 1080}]\nproxy-groups: [{name: Auto, type: url-test, proxies: [n], url: 'http://127.0.0.1:1/'}]\nrules: ['MATCH,Auto']\n"
	p := fullPreview(t, h, remote, "")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	var root map[string]any
	_ = json.Unmarshal([]byte(h.doc.text), &root)
	g := root["kernel"].(map[string]any)["groups"].([]any)[0].(map[string]any)
	g["type"] = "smart"
	g["smart"] = map[string]any{"scope": "group", "exploration_rate": .02}
	g["damping"] = map[string]any{"relative_improvement": .3, "confirm_rounds": 3, "min_dwell": "90s"}
	g["tolerance"] = "75ms"
	b, _ := json.Marshal(root)
	if _, e := h.Apply(string(b)); e != nil {
		t.Fatal(e)
	}
	refreshed := fullPreview(t, h, strings.Replace(remote, "1080", "1081", 1), p.ID)
	if _, e := h.Apply(refreshed.Text); e != nil {
		t.Fatal(e)
	}
	found := false
	for _, g := range h.doc.config.Groups {
		if g.Smart != nil {
			found = true
			if g.Smart.Scope != "group" || g.Smart.ExplorationRate != .02 || g.Damping == nil || g.Damping.ConfirmRounds != 3 || g.Tolerance.Value() != 75*time.Millisecond {
				t.Fatal("smart override lost", g)
			}
		}
	}
	if !found {
		t.Fatal("smart fields disappeared")
	}
}
func TestK1SelectionDeltaOnlyManualFields(t *testing.T) {
	// Selection changes are computed independently of automatic runtime state.
	h := newHost(t)
	before, e := parseDocument(fixture(t, map[string]any{"groups": []any{map[string]any{"name": "S", "type": "select", "members": []string{"direct"}}}}), h.workspace)
	if e != nil {
		t.Fatal(e)
	}
	after := before.config
	after.Groups = append(after.Groups[:0:0], before.config.Groups...)
	after.Groups[0].Selected = "direct"
	if got := manualSelectionChanges(before.config, after); len(got) != 1 || got[0] != "S" {
		t.Fatal(got)
	}
	if got := manualSelectionChanges(after, after); len(got) != 0 {
		t.Fatal("no-op detected as switch")
	}

	beforePin := after
	beforePin.Groups = append(beforePin.Groups[:0:0], after.Groups...)
	beforePin.Groups[0].Type = "smart"
	beforePin.Groups[0].Selected = ""
	pinned := beforePin
	pinned.Groups = append(pinned.Groups[:0:0], beforePin.Groups...)
	pinned.Groups[0].Fixed = "direct"
	for _, pair := range [][2]kernel.Config{{beforePin, pinned}, {pinned, beforePin}} {
		if got := manualSelectionChanges(pair[0], pair[1]); len(got) != 1 || got[0] != "S" {
			t.Fatal("pin/unpin not detected", got)
		}
	}
}
func TestK1AllNodeProbeCommitsComparableGroupsAtomically(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 2 {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(204)
	}))
	defer target.Close()
	k := settingsKernel(t)
	k["groups"].([]any)[0].(map[string]any)["probe"].(map[string]any)["url"] = target.URL
	h, _ := startSettings(t, k, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := h.server.ProbeNodesWithPolicy(ctx, []string{"direct", "p"}, target.URL, h.manualPolicy, 2, time.Second, nil)
		done <- e
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("no second probe")
	}
	for _, g := range h.server.GroupSnapshots() {
		for _, m := range g.Members {
			if m.Probed {
				t.Fatal("all-node workers committed a partial group")
			}
		}
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	for _, g := range h.server.GroupSnapshots() {
		for _, m := range g.Members {
			if !m.Probed || !m.ProbeOK || m.ScoreParts.ProbeMS == nil {
				t.Fatal("complete comparable group not updated")
			}
		}
	}
}

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

func beginAllProbeTest(t *testing.T, h *Host, ctx context.Context) *probeRound {
	t.Helper()
	v, e := h.probeAll(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if v.(map[string]any)["started"] != true {
		t.Fatal(v)
	}
	h.mu.Lock()
	r := h.allRound
	h.mu.Unlock()
	if r == nil {
		t.Fatal("batch finished before test capture")
	}
	return r
}
func waitAllProbeTest(t *testing.T, r *probeRound) {
	t.Helper()
	select {
	case <-r.finished:
	case <-time.After(45 * time.Second):
		t.Fatal("batch did not finish")
	}
}
func batchKernel(t *testing.T, n int) map[string]any {
	t.Helper()
	k := settingsKernel(t)
	base := k["outbounds"].([]any)[0].(map[string]any)
	outs := []any{}
	for i := range n {
		node := map[string]any{}
		for k, v := range base {
			node[k] = v
		}
		node["name"] = fmt.Sprintf("n%02d", i)
		outs = append(outs, node)
	}
	k["outbounds"] = outs
	delete(k, "groups")
	return k
}

// Real second-scale HTTP behind the ordinary SOCKS outbound. Ten nodes exceed
// twice the two workers; the batch runs >10s, while each healthy target is 1-4s.
func TestR5AllProbeIndependentSecondsAndGenuineTimeout(t *testing.T) {
	var ordinal, in, maximum atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seq := ordinal.Add(1)
		n := in.Add(1)
		defer in.Add(-1)
		for {
			m := maximum.Load()
			if n <= m || maximum.CompareAndSwap(m, n) {
				break
			}
		}
		delay := time.Duration((seq-1)%4+1) * time.Second
		if seq == 10 || r.URL.Path == "/timeout" {
			delay = 6 * time.Second
		}
		select {
		case <-time.After(delay):
			w.WriteHeader(204)
		case <-r.Context().Done():
		}
	}))
	defer target.Close()
	h, _ := startSettings(t, batchKernel(t, 10), map[string]any{"probe_url": target.URL, "probe_timeout": "5s", "probe_round_timeout": "10s", "probe_concurrency": 2})
	ctx, cancel := context.WithCancel(context.Background())
	before := time.Now()
	round := beginAllProbeTest(t, h, ctx)
	if time.Since(before) > time.Second {
		t.Fatal("admission blocked on whole batch")
	}
	cancel() // accepted job is not tied to a wire/request deadline
	last := 0
	for {
		p, _ := round.projection()
		done := p["done"].(int)
		if done < last || done > 10 {
			t.Fatal("non-monotonic completions", last, done)
		}
		last = done
		select {
		case <-round.finished:
			goto finished
		case <-time.After(20 * time.Millisecond):
		}
	}
finished:
	elapsed := time.Since(before)
	p, rs := round.projection()
	if elapsed < 10*time.Second || elapsed > 35*time.Second || maximum.Load() != 2 || ordinal.Load() != 10 || p["done"] != 10 || len(p["names"].([]string)) != 0 {
		t.Fatal(elapsed, maximum.Load(), ordinal.Load(), p)
	}
	good, bad := 0, 0
	for name, r := range rs {
		if r.ProbeMS != nil && r.ErrorCode == "" {
			good++
		} else {
			bad++
			if r.ErrorCode != "PROBE_TARGET_TIMEOUT" || r.ErrorStage != "target" {
				t.Fatal("queue was mislabeled failed", name, r)
			}
		}
	}
	if good != 9 || bad != 1 {
		t.Fatal("expected nine healthy targets and one genuine timeout", good, bad, rs)
	}
	h.mu.Lock()
	if len(h.probes) != 10 || h.allRound != nil {
		t.Fatal("final results not published")
	}
	h.mu.Unlock()
	// The same single-node operation still uses 5s target/10s own-round and the
	// identical failure category; group budget regressions remain unchanged.
	v, e := h.probe(context.Background(), false, "n00", target.URL+"/timeout")
	if e != nil {
		t.Fatal(e)
	}
	one := v.(kernel.ProbeResult)
	if one.ErrorCode != "PROBE_TARGET_TIMEOUT" || one.ErrorStage != "target" {
		t.Fatal(one)
	}
	t.Logf("10 nodes / concurrency2: healthy=%d true-timeout=%d elapsed=%s; no shared 10s batch cutoff", good, bad, elapsed)
}

func TestR5BatchAdmissionNoDuplicateManualProbes(t *testing.T) {
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
			w.WriteHeader(204)
		case <-r.Context().Done():
		}
	}))
	defer target.Close()
	h, _ := startSettings(t, batchKernel(t, 3), map[string]any{"probe_url": target.URL, "probe_timeout": "2s", "probe_round_timeout": "3s", "probe_concurrency": 1})
	single := make(chan struct{})
	go func() { h.probe(context.Background(), false, "n00", ""); close(single) }()
	waitSignal(t, entered)
	if _, e := h.probeAll(context.Background(), nil); e == nil || e.Code != "probe_busy" {
		t.Fatal("batch overlapped single", e)
	}
	close(release)
	waitSignal(t, single)
	// Second server holds every target so duplicate requests can be asserted.
	hold := make(chan struct{})
	holdEntered := make(chan struct{}, 4)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		holdEntered <- struct{}{}
		select {
		case <-hold:
			w.WriteHeader(204)
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	h.mu.Lock()
	h.doc.client.ProbeURL = slow.URL
	h.mu.Unlock()
	round := beginAllProbeTest(t, h, context.Background())
	waitSignal(t, holdEntered)
	for range 3 {
		if _, e := h.probeAll(context.Background(), nil); e == nil || e.Code != "probe_busy" {
			t.Fatal("duplicate batch admitted", e)
		}
		if _, e := h.probe(context.Background(), false, "n00", ""); e == nil || e.Code != "probe_busy" {
			t.Fatal("single overlapped batch", e)
		}
	}
	h.Status()
	close(hold)
	waitAllProbeTest(t, round)
	// Admission and permits have drained; a subsequent ordinary single works.
	if _, e := h.probe(context.Background(), false, "n00", target.URL); e != nil {
		t.Fatal("busy gate stuck", e)
	}
	if calls.Load() != 2 {
		t.Fatal("single was duplicated", calls.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := h.probeAll(ctx, nil); e == nil || e.Code != "request_canceled" {
		t.Fatal("canceled admission launched a job", e)
	}
}

func TestR5BatchApplyAndCloseDiscardOldProgress(t *testing.T) {
	for _, action := range []string{"apply", "close"} {
		t.Run(action, func(t *testing.T) {
			entered := make(chan struct{}, 4)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
			defer target.Close()
			h, text := startSettings(t, batchKernel(t, 6), map[string]any{"probe_url": target.URL, "probe_timeout": "5s", "probe_round_timeout": "10s", "probe_concurrency": 2})
			round := beginAllProbeTest(t, h, context.Background())
			waitSignal(t, entered)
			before := time.Now()
			if action == "apply" {
				// A full apply must actually change a non-selection field.
				text = settingsText(t, text, map[string]any{"probe_concurrency": 3})
				if _, e := h.Apply(text); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := h.Close(); e != nil {
					t.Fatal(e)
				}
			}
			waitAllProbeTest(t, round)
			if time.Since(before) > 2*time.Second {
				t.Fatal("epoch cancellation did not drain promptly")
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if len(h.probes) != 0 || h.allRound != nil {
				t.Fatal("old epoch published results/progress")
			}
		})
	}
}

func TestR9OriginalLabelsStableIDsRefreshPreservesEverything(t *testing.T) {
	h := fullHost(t)
	text := strings.ReplaceAll(fullFixture, "name: n,", "name: '🇭🇰 Flower',")
	text = strings.ReplaceAll(text, "[n, DIRECT]", "['🇭🇰 Flower', DIRECT]")
	text += ""
	p := fullPreview(t, h, text, "")
	if _, e := h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	root, _ := sourceJSON(h.doc)
	subs, _ := subscriptionsOf(root)
	id := subs[0].Names["🇭🇰 Flower"]
	if id == "" || id == "🇭🇰 Flower" {
		t.Fatal("stable safe ID required")
	}
	var d map[string]any
	json.Unmarshal([]byte(h.doc.text), &d)
	k := d["kernel"].(map[string]any)
	g := k["groups"].([]any)[0].(map[string]any)
	g["selected"] = id
	k["outbounds"] = append(k["outbounds"].([]any), map[string]any{"name": "manual", "type": "socks5", "server": "manual.invalid", "port": 9})
	k["routing"].(map[string]any)["rules"] = append(k["routing"].(map[string]any)["rules"].([]any), map[string]any{"domain": "manual.invalid", "outbound": id})
	b, _ := json.Marshal(d)
	if _, e := h.Apply(string(b)); e != nil {
		t.Fatal(e)
	}
	ms := 31.0
	h.probes[id] = kernel.ProbeResult{Name: id, ProbeMS: &ms, At: time.Now()}
	next := fullPreview(t, h, text, p.ID)
	if _, e := h.Apply(next.Text, next.Format); e != nil {
		t.Fatal(e)
	}
	if h.doc.config.Groups[0].Selected != id || func() bool {
		label, manual := false, false
		for _, o := range h.doc.config.Outbounds {
			label = label || o.FilterName == "🇭🇰 Flower"
			manual = manual || o.Name == "manual"
		}
		return !label || !manual
	}() || h.probes[id].ProbeMS == nil {
		t.Fatal("refresh lost original label/selection/manual/history", h.doc.config.Groups[0], h.probes)
	}
	found := false
	for _, r := range h.doc.config.Routing.Rules {
		if r.Domain == "manual.invalid" && r.Outbound == id {
			found = true
		}
	}
	if !found {
		t.Fatal("manual rule reference changed")
	}
	out, e := h.filterPreview(rawJSON(map[string]any{"filter": "(?i)^🇭🇰 Flower$"}))
	if e != nil || len(out.(map[string]any)["names"].([]string)) != 1 || out.(map[string]any)["names"].([]string)[0] != id {
		t.Fatal("regex must use exact original", out, e)
	}
}
func TestR9OriginalFixedAndWeightsSurviveRefresh(t *testing.T) {
	h := fullHost(t)
	text := strings.Replace(fullFixture, "type: select, proxies: [n, DIRECT]", "type: url-test, proxies: [n, DIRECT], url: https://example.org/204", 1)
	p := fullPreview(t, h, text, "")
	if _, e := h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	root, _ := sourceJSON(h.doc)
	var k map[string]json.RawMessage
	json.Unmarshal(root["kernel"], &k)
	a := rawArray(k, "groups")
	var g map[string]any
	json.Unmarshal(a[0], &g)
	g["fixed"] = "n"
	g["priority"] = map[string]float64{"n": 1.5}
	a[0] = rawJSON(g)
	k["groups"] = rawJSON(a)
	root["kernel"] = rawJSON(k)
	if _, e := h.Apply(string(rawJSON(root))); e != nil {
		t.Fatal(e)
	}
	next := fullPreview(t, h, text, p.ID)
	if _, e := h.Apply(next.Text, next.Format); e != nil {
		t.Fatal(e)
	}
	g2 := h.doc.config.Groups[0]
	if g2.Fixed != "n" || g2.Priority["n"] != 1.5 {
		t.Fatal("fixed/weight lost", g2)
	}
}
func TestR9MetadataTitleOrderAndPrivacyBounds(t *testing.T) {
	for _, tc := range []struct{ title, disposition, url, want string }{{"base64:" + base64.StdEncoding.EncodeToString([]byte("我的订阅")), `attachment; filename="file.yaml"`, "https://example.org/sub.yaml?token=SECRET", "我的订阅"}, {"", `attachment; filename*=UTF-8''%E8%AE%A2%E9%98%85.yaml`, "https://example.org/path?token=SECRET", "订阅.yaml"}, {"", "", "https://example.org/a/sub.yaml?token=SECRET", "sub.yaml"}, {"", "", "https://example.org/?token=SECRET", "example.org"}, {"bad\nname", "", "https://example.org/", "example.org"}} {
		ctx := context.WithValue(context.Background(), subscriptionHeadersKey{}, &subscriptionHeaders{title: tc.title, disposition: tc.disposition})
		if got := subscriptionName(ctx, tc.url); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
	meta := &subscriptionHeaders{}
	ctx := context.WithValue(context.Background(), subscriptionHeadersKey{}, meta)
	_, e := fetchImportBounded(ctx, "https://example.org/config", nil, func(*http.Transport) http.RoundTripper {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Profile-Title": []string{"recognized"}}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
		})
	}, 1024)
	if e != nil || meta.title != "recognized" {
		t.Fatal(meta, e)
	}
}
func TestR9SubscriptionRouteAndAutoUpdatePersistWithAutomaticRename(t *testing.T) {
	h := fullHost(t)
	h.fullFetch = func(ctx context.Context, _ string, _ *clientegress.Policy, _ int64) ([]byte, error) {
		if m, ok := ctx.Value(subscriptionHeadersKey{}).(*subscriptionHeaders); ok {
			m.title = "识别订阅"
		}
		return []byte(fullFixture), nil
	}
	v, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"url": "https://example.org/config?token=SECRET", "use_system_proxy": true, "auto_update": false}))
	if e != nil {
		t.Fatal(e)
	}
	p := v.(subscriptionPreview)
	if _, e = h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	root, _ := sourceJSON(h.doc)
	subs, _ := subscriptionsOf(root)
	if subs[0].Name != "识别订阅" || !subs[0].UseSystemProxy || subs[0].AutoUpdate == nil || *subs[0].AutoUpdate {
		t.Fatal(subs[0].Name)
	}
	// Legacy automatic name is upgraded, user-authored name preserved.
	for _, tc := range []struct{ old, want string }{{"完整配置 abcdef", "识别订阅"}, {"我自己起的名", "我自己起的名"}} {
		subs[0].Name = tc.old
		root["subscriptions"] = rawJSON(subs)
		if _, e = h.Apply(string(rawJSON(root))); e != nil {
			t.Fatal(e)
		}
		q, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"id": p.ID}))
		if e != nil {
			t.Fatal(e)
		}
		next := q.(subscriptionPreview)
		if _, e = h.Apply(next.Text, next.Format); e != nil {
			t.Fatal(e)
		}
		root, _ = sourceJSON(h.doc)
		subs, _ = subscriptionsOf(root)
		if subs[0].Name != tc.want || !subs[0].UseSystemProxy {
			t.Fatal("metadata refresh lost saved route/name")
		}
	}
}
func TestR9DesktopDNSAndUnifiedDefaultsOnlyProjection(t *testing.T) {
	d, e := parseDocument(initialDocument, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if d.config.DNS == nil || d.config.DNS.Server != "system" || strings.Contains(d.text, "unified_delay") {
		t.Fatal("desktop defaults not projected")
	}
	custom := strings.Replace(initialDocument, `"kernel":{}`, `"kernel":{"dns":{"servers":["8.8.8.8","1.1.1.1"]}}`, 1)
	d, e = parseDocument(custom, t.TempDir())
	if e != nil || len(d.config.DNS.Servers) != 2 {
		t.Fatal("explicit user DNS lost", e)
	}
	for _, raw := range []string{`null`, `"true"`, `1`} {
		text := strings.Replace(initialDocument, `"mode":"rule"`, `"mode":"rule","unified_delay":`+raw, 1)
		if _, e := parseDocument(text, t.TempDir()); e == nil {
			t.Fatal("invalid unified accepted", raw)
		}
	}
}
func TestR9StoppedIconProxyThenDirectAndGroupLog(t *testing.T) {
	for _, mode := range []string{"proxy", "direct", "fallback"} {
		t.Run(mode, func(t *testing.T) {
			h := fullHost(t)
			var routes []bool
			h.iconTransport = func(tr *http.Transport) http.RoundTripper {
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					proxied := bootstrapFrom(req.Context()) != nil
					routes = append(routes, proxied)
					if proxied && mode == "fallback" {
						return nil, dl("proxy_connect", "proxy_http")
					}
					return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`<svg xmlns="http://www.w3.org/2000/svg"/>`))}, nil
				})
			}
			p := map[string]any{"url": "https://raw.githubusercontent.com/public/icon.png?token=SECRET"}
			if mode != "direct" {
				p["_system_proxy"] = bootstrapProxy{Host: "127.0.0.1", Port: 7890}
				p["_egress"] = bootstrapEgress{Generation: 0, Enabled: false}
			}
			v, e := h.getIcon(context.Background(), rawJSON(p))
			if e != nil || !strings.HasPrefix(v.(map[string]any)["data_uri"].(string), "data:image/svg+xml;") {
				t.Fatal("route did not return image", e)
			}
			if mode == "proxy" && (len(routes) != 1 || !routes[0]) || mode == "direct" && (len(routes) != 1 || routes[0]) || mode == "fallback" && (len(routes) != 2 || !routes[0] || routes[1]) {
				t.Fatal("wrong priority", routes)
			}
			if mode == "fallback" {
				l := h.logs.read(0, 500)
				if len(l.Entries) != 1 || l.Entries[0].Code != "proxy_http" {
					t.Fatal("proxy failure invisible", l)
				}
			}
		})
	}
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	h.Apply(p.Text, p.Format)
	h.iconFetch = func(context.Context, string) ([]byte, error) { return nil, errors.New("https://secret/?token=SECRET") }
	h.getIcon(context.Background(), rawJSON(map[string]any{"url": "https://example.org/icon", "group": "pick"}))
	l := h.logs.read(0, 500)
	if len(l.Entries) != 1 || l.Entries[0].Group != "pick" {
		t.Fatal("group missing", l)
	}
	b, _ := json.Marshal(l)
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "https:") {
		t.Fatal("private data escaped")
	}
}
func TestR9IconProxySeamStillSendsHostnameCONNECTWithoutLocalResolve(t *testing.T) {
	h := fullHost(t)
	calls := 0
	h.iconTransport = func(tr *http.Transport) http.RoundTripper {
		tr.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialBootstrapIO(ctx, address, bootstrapFrom(ctx), nil, func(context.Context, string) ([]netip.Addr, error) {
				t.Error("target resolver called")
				return []netip.Addr{netip.MustParseAddr("198.18.1.1")}, nil
			}, nil, func(context.Context, *net.Dialer, string) (net.Conn, error) {
				a, b := net.Pipe()
				go func() {
					defer b.Close()
					reader := bufio.NewReader(b)
					req, e := http.ReadRequest(reader)
					if e != nil {
						return
					}
					if req.Method != "CONNECT" || req.Host != "icons.example.org:80" {
						t.Error("hostname not delegated")
					}
					calls++
					io.WriteString(b, "HTTP/1.1 200 Connection established\r\n\r\n")
					req, e = http.ReadRequest(reader)
					if e == nil {
						body := `<svg xmlns="http://www.w3.org/2000/svg"/>`
						io.WriteString(b, "HTTP/1.1 200 OK\r\nContent-Length: "+fmt.Sprint(len(body))+"\r\nConnection: close\r\n\r\n"+body)
					}
				}()
				return a, nil
			}, func(net.Conn) error { return nil })
		}
		return tr
	}
	v, e := h.getIcon(context.Background(), rawJSON(map[string]any{"url": "http://icons.example.org/icon", "_system_proxy": bootstrapProxy{Host: "127.0.0.1", Port: 7890}, "_egress": bootstrapEgress{}}))
	if e != nil || v.(map[string]any)["data_uri"] == "" || calls != 1 {
		t.Fatal("real HTTP tunnel failed", calls, e)
	}
}

func TestR9UnifiedDefaultAndExplicitOffManualAndHealth(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			var calls atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "HEAD" {
					t.Error("client health must use HEAD")
				}
				calls.Add(1)
				w.WriteHeader(204)
			}))
			defer target.Close()
			h := fullHost(t)
			k := map[string]any{"security": map[string]any{"allow_loopback": true}, "groups": []any{map[string]any{"name": "auto", "type": "url-test", "members": []string{"direct"}, "lazy": false, "probe": map[string]any{"url": target.URL, "interval": "1h"}}}}
			text := fixture(t, k)
			if !enabled {
				text = settingsText(t, text, map[string]any{"unified_delay": false})
			}
			if _, e := h.Apply(text); e != nil {
				t.Fatal(e)
			}
			if _, e := h.Start(); e != nil {
				t.Fatal(e)
			}
			want := int32(1)
			if enabled {
				want = 2
			}
			deadline := time.Now().Add(2 * time.Second)
			for calls.Load() < want && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if calls.Load() != want {
				t.Fatal("health semantics", calls.Load(), want)
			}
			if _, e := h.probe(context.Background(), false, "direct", target.URL); e != nil {
				t.Fatal(e)
			}
			if calls.Load() != 2*want {
				t.Fatal("manual semantics differs from health", calls.Load(), want)
			}
		})
	}
}
