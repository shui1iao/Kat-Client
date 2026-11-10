package clientcore

import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/kernel"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

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
