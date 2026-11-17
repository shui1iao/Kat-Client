package clientcore

import (
	"encoding/json"
	"github.com/shui1iao/Kat/internal/kernel"
	"gopkg.in/yaml.v3"
	"strings"
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
