package clientcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/oschwald/maxminddb-golang"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/route"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFullSubscriptionResourceNeedScan(t *testing.T) {
	for _, v := range []struct {
		content      string
		country, asn bool
	}{{"payload: ['DOMAIN,geoip.invalid']", false, false}, {"payload: ['GEOIP,LAN']", false, false}, {"payload: ['GEOIP,CN']", true, false}, {"payload: ['IP-ASN,13335,no-resolve']", false, true}, {"payload: ['OR,((GEOIP,CN),(IP-ASN,13335))']", true, true}} {
		c, a, e := subscriptionSetNeeds(route.RuleSetOptions{Format: "yaml", Behavior: "classical"}, []byte(v.content))
		if e != nil || c != v.country || a != v.asn {
			t.Fatal("database requirement mismatch")
		}
	}
	h := fullHost(t)
	calls := 0
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) { calls++; return nil, nil }
	fullPreview(t, h, fullFixture, "")
	if calls != 0 {
		t.Fatal("unreferenced database downloaded")
	}
}
func TestFullSubscriptionRealCountryAndASNFields(t *testing.T) {
	dir := os.Getenv("KAT_RESOURCE_EVIDENCE")
	if dir == "" {
		t.Skip("explicit downloaded resource path required")
	}
	for _, v := range []struct {
		kind, file, ip, country string
		asn                     uint32
	}{{"geoip", "country.mmdb", "223.5.5.5", "CN", 0}, {"asn", "asn.mmdb", "1.1.1.1", "", 13335}, {"asn", "asn.mmdb", "8.8.8.8", "", 15169}} {
		b, e := os.ReadFile(filepath.Join(dir, v.file))
		if e != nil || validateSubscriptionDB(v.kind, b) != nil {
			t.Fatal("actual MMDB incompatible")
		}
		db, e := maxminddb.FromBytes(b)
		if e != nil {
			t.Fatal(e)
		}
		var record struct {
			Country struct {
				ISO string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
			ASN uint32 `maxminddb:"autonomous_system_number"`
		}
		if db.Lookup(net.ParseIP(v.ip), &record) != nil {
			t.Fatal("MMDB field lookup failed")
		}
		if v.country != "" && record.Country.ISO != v.country || v.asn != 0 && record.ASN != v.asn {
			t.Fatal("actual MMDB field value mismatch")
		}
		sum := sha256.Sum256(b)
		t.Logf("resource=%s bytes=%d sha256=%s ip_version=%d nodes=%d country_field=%s asn_field=%d", v.file, len(b), hex.EncodeToString(sum[:]), db.Metadata.IPVersion, db.Metadata.NodeCount, record.Country.ISO, record.ASN)
		db.Close()
	}
	if validateSubscriptionDB("asn", []byte("not a database")) == nil {
		t.Fatal("malformed ASN database accepted")
	}
}
func TestFullSubscriptionURLUpgradeAndRefreshPersistence(t *testing.T) {
	h := fullHost(t)
	url := "https://subscription.example.invalid/full"
	doc := strings.Replace(initialDocument, `"kernel":{}`, `"kernel":{"providers":[{"name":"old","type":"http","url":"`+url+`","interval":"2h"}]}`, 1)
	if _, e := applyLegacyFixture(h, doc); e != nil {
		t.Fatal(e)
	}
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return []byte(fullFixture), nil
	}
	v, e := h.previewSubscription(context.Background(), rawJSON(map[string]string{"url": url}))
	if e != nil {
		t.Fatal(e)
	}
	p := v.(subscriptionPreview)
	if !p.NeedsConfirmation {
		t.Fatal("provider upgrade omitted preview")
	}
	if _, e := applyLegacyFixture(h, p.Text); e != nil {
		t.Fatal(e)
	}
	if len(h.doc.config.Providers) != 0 {
		t.Fatal("duplicated nodes-only provider")
	}
	root, _ := sourceJSON(h.doc)
	owners, _ := subscriptionsOf(root)
	if len(owners) != 1 || owners[0].URL != url || owners[0].Interval != 7200 {
		t.Fatal("URL/refresh ownership not saved")
	}
	v, e = h.previewSubscription(context.Background(), rawJSON(map[string]string{"id": p.ID}))
	if e != nil {
		t.Fatal(e)
	}
	q := v.(subscriptionPreview)
	if q.NeedsConfirmation {
		t.Fatal("ordinary no-conflict refresh prompts")
	}
	if _, e := applyLegacyFixture(h, q.Text); e != nil {
		t.Fatal(e)
	}
	if len(h.doc.config.Outbounds) != 1 {
		t.Fatal("repeated refresh appended")
	}
}
func TestFullSubscriptionPreviewLegacyAndNative(t *testing.T) {
	h := fullHost(t)
	for _, s := range []struct{ text, kind string }{{initialDocument, "native"}, {"socks5://127.0.0.1:1080#local", "nodes"}} {
		v, e := h.previewSubscription(context.Background(), rawJSON(map[string]string{"text": s.text}))
		if e != nil {
			t.Fatal(e)
		}
		if v.(subscriptionPreview).Kind != s.kind {
			t.Fatal("wrong import kind")
		}
	}
	v, e := h.previewSubscription(context.Background(), rawJSON(map[string]string{"text": "proxies: []\nrules: ['PROCESS-UNSUPPORTED,x,a']"}))
	if e != nil {
		t.Fatal(e)
	}
	p := v.(subscriptionPreview)
	if len(p.Issues) == 0 || p.Kind != "full" {
		t.Fatal("unsupported full input became a nodes subset")
	}
}

func TestFullSubscriptionIPCBudget(t *testing.T) {
	if requestBudget("subscription.preview") != 185*time.Second {
		t.Fatal("preview RPC truncates bounded downloads")
	}
	if requestBudget("subscription.cancel") != 35*time.Second {
		t.Fatal("cancel unexpectedly slow")
	}
}

func TestFullSubscriptionAliasCannotFallbackToNodes(t *testing.T) {
	h := fullHost(t)
	v, e := h.previewSubscription(context.Background(), rawJSON(map[string]string{"text": "proxies: &nodes []\nproxy-groups: *nodes\nrules: ['MATCH,DIRECT']\n"}))
	if e != nil {
		t.Fatal(e)
	}
	p := v.(subscriptionPreview)
	if p.Kind != "full" || len(p.Issues) == 0 || p.NodeImport != nil {
		t.Fatal("unsafe full YAML fell back to nodes-only")
	}
}
