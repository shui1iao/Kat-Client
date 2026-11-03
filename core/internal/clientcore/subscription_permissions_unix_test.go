//go:build !windows

package clientcore

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/route"
)

func sharedSubscriptionFile(t *testing.T, data []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "shared-resource")
	if e := os.WriteFile(p, data, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, mode); e != nil {
		t.Fatal(e)
	}
	return p
}
func assertSharedSubscriptionFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	st, e := os.Stat(path)
	if e != nil || st.Mode().Perm() != mode {
		t.Fatal("subscription resource read changed external permissions")
	}
	b, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(b, data) {
		t.Fatal("subscription resource read changed external bytes")
	}
}
func setSharedSubscriptionDBs(t *testing.T, h *Host, paths map[string]string) {
	t.Helper()
	root, _ := sourceJSON(h.doc)
	k := map[string]json.RawMessage{}
	for kind, path := range paths {
		k[kind] = rawJSON(route.GeoIPOptions{Path: path})
	}
	root["kernel"] = rawJSON(k)
	if _, e := h.Apply(string(rawJSON(root))); e != nil {
		t.Fatal(e)
	}
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		t.Fatal("existing local resources must not trigger a download")
		return nil, nil
	}
}
func TestFullSubscriptionExternalDatabaseFailurePreservesPermissions(t *testing.T) {
	for _, kind := range []string{"geoip", "asn"} {
		for _, mode := range []os.FileMode{0644, 0444} {
			name := kind + "/shared"
			if mode == 0444 {
				name = kind + "/readonly"
			}
			t.Run(name, func(t *testing.T) {
				h := fullHost(t)
				data := []byte("not an MMDB\n")
				p := sharedSubscriptionFile(t, data, mode)
				setSharedSubscriptionDBs(t, h, map[string]string{kind: p})
				before := h.doc.text
				rule := "GEOIP,CN,DIRECT"
				if kind == "asn" {
					rule = "IP-ASN,13335,DIRECT"
				}
				_, err := h.previewSubscription(context.Background(), rawJSON(map[string]string{"text": "proxies: []\nrules: ['" + rule + "','MATCH,DIRECT']\n"}))
				if err == nil || err.Code != "subscription_resource_failed" {
					t.Fatal("invalid shared DB was accepted")
				}
				assertSharedSubscriptionFile(t, p, data, mode)
				disk, e := os.ReadFile(h.path)
				if e != nil || string(disk) != before || h.doc.text != before || h.fullPending != nil {
					t.Fatal("failed preview changed source/owner or left a stage")
				}
			})
		}
	}
}
func TestFullSubscriptionExternalDatabasePreviewCancelPreservesPermissions(t *testing.T) {
	dir := os.Getenv("KAT_RESOURCE_EVIDENCE")
	if dir == "" {
		t.Skip("explicit actual MMDB evidence path required")
	}
	country, e := os.ReadFile(filepath.Join(dir, "country.mmdb"))
	if e != nil {
		t.Fatal(e)
	}
	asn, e := os.ReadFile(filepath.Join(dir, "asn.mmdb"))
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []os.FileMode{0644, 0444} {
		name := "shared"
		if mode == 0444 {
			name = "readonly"
		}
		t.Run(name, func(t *testing.T) {
			h := fullHost(t)
			cp := sharedSubscriptionFile(t, country, mode)
			ap := sharedSubscriptionFile(t, asn, mode)
			setSharedSubscriptionDBs(t, h, map[string]string{"geoip": cp, "asn": ap})
			before := h.doc.text
			p := fullPreview(t, h, "proxies: []\nrules: ['GEOIP,CN,DIRECT','IP-ASN,13335,DIRECT','MATCH,DIRECT']\n", "")
			assertSharedSubscriptionFile(t, cp, country, mode)
			assertSharedSubscriptionFile(t, ap, asn, mode)
			stage := h.fullPending.Dir
			if _, err := h.cancelSubscription(rawJSON(map[string]string{"token": p.Token})); err != nil {
				t.Fatal(err)
			}
			if _, e := os.Stat(stage); !os.IsNotExist(e) {
				t.Fatal("canceled private stage retained")
			}
			assertSharedSubscriptionFile(t, cp, country, mode)
			assertSharedSubscriptionFile(t, ap, asn, mode)
			disk, e := os.ReadFile(h.path)
			if e != nil || string(disk) != before || h.doc.text != before {
				t.Fatal("preview or cancel changed source/ownership")
			}
		})
	}
}
func TestFullSubscriptionExternalRuleCacheValidationPreservesPermissions(t *testing.T) {
	for _, valid := range []bool{true, false} {
		for _, mode := range []os.FileMode{0644, 0444} {
			name := "valid"
			if !valid {
				name = "invalid"
			}
			if mode == 0444 {
				name += "/readonly"
			} else {
				name += "/shared"
			}
			t.Run(name, func(t *testing.T) {
				data := []byte("payload: ['DOMAIN,controlled.invalid']\n")
				if !valid {
					data = []byte("payload: ['PROCESS-UNSUPPORTED,no']\n")
				}
				p := sharedSubscriptionFile(t, data, mode)
				rs := route.RuleSetOptions{Name: "shared", Path: p, Format: "yaml", Behavior: "classical"}
				owner := fullSubscription{Snapshot: fullSnapshot{RuleSets: []json.RawMessage{rawJSON(rs)}}}
				e := validateSubscriptionResources(kernel.Config{RuleSets: []kernel.RuleSetConfig{kernel.RuleSetConfig(rs)}}, owner)
				if (e == nil) != valid {
					t.Fatal("rule cache validation result changed")
				}
				assertSharedSubscriptionFile(t, p, data, mode)
			})
		}
	}
}
