package provider

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestSubscriptionURIBudgetsPreserveTotals(t *testing.T) {
	list := "socks://one.invalid:1080#one\n" + strings.Repeat("other://unsupported\n", MaxURIEntries-1) + "socks://two.invalid:1080#two\n"
	for _, s := range []string{list, base64.StdEncoding.EncodeToString([]byte(list))} {
		r, e := Parse([]byte(s), FormatAuto)
		if e != nil || len(r.Nodes) != 1 || r.SkippedTotal != MaxURIEntries || len(r.Skipped) != MaxSkippedDetails {
			t.Fatalf("nodes=%d skipped=%d details=%d err=%v", len(r.Nodes), r.SkippedTotal, len(r.Skipped), e)
		}
	}
	r, e := Parse([]byte("socks://"+strings.Repeat("a", MaxURIBytes)+"\nsocks://one.invalid:1#one"), FormatAuto)
	if e != nil || r.SkippedTotal != 1 || !strings.Contains(r.Skipped[0].Reason, "size limit") || len(r.Nodes) != 1 {
		t.Fatal("line budget")
	}
	if BeginsURIList([]byte("url://comment: unused\nproxies: []")) {
		t.Fatal("ambiguous YAML mapping lost")
	}
}
func TestSubscriptionRejectSPKIPin(t *testing.T) {
	for _, typ := range []string{"trojan", "anytls"} {
		for _, insecure := range []bool{true, false} {
			b := []byte(fmt.Sprintf(`[{"type":%q,"tag":"n","server":"node.invalid","server_port":443,"password":"x","tls":{"enabled":true,"insecure":%t,"certificate_public_key_sha256":["test"]}}]`, typ, insecure))
			r, e := Parse(b, FormatSingBox)
			if e != nil || len(r.Nodes) != 0 || r.SkippedTotal != 1 || !strings.Contains(r.Skipped[0].Reason, "certificate_public_key_sha256") {
				t.Fatalf("pin must be explicitly rejected: %v %+v", e, r.Skipped)
			}
		}
	}
}
