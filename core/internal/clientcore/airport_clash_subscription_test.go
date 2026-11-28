package clientcore

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/shui1iao/Kat/internal/provider"
	"strings"
	"testing"
)

func TestAirportClashLargeSubscriptionImport(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n")
	var names []string
	for i := 1; i <= 80; i++ {
		n := fmt.Sprintf("HK-%02d", i)
		if i == 1 {
			// Include a control character that safeSubscriptionName must strip.
			n = "🇭🇰 香港 01 | IPLC | 1.5x"
		}
		names = append(names, n)
		fmt.Fprintf(&b, "  - {name: %q, type: ss, server: example.org, port: %d, cipher: aes-128-gcm, password: secret}\n", n, 10000+i)
	}
	b.WriteString("proxy-groups:\n")
	b.WriteString("  - name: Proxy\n    type: select\n    url: https://www.gstatic.com/generate_204\n    interval: 300\n    proxies:\n      - Auto\n      - Fallback\n      - DIRECT\n      - DIRECT\n")
	for _, n := range names {
		fmt.Fprintf(&b, "      - %q\n", n)
	}
	b.WriteString("  - name: Auto\n    type: url-test\n    url: https://www.gstatic.com/generate_204\n    interval: 300\n    tolerance: 50\n    proxies:\n")
	for _, n := range names {
		fmt.Fprintf(&b, "      - %q\n", n)
	}
	b.WriteString("  - name: Fallback\n    type: fallback\n    url: https://www.gstatic.com/generate_204\n    interval: 300\n    tolerance: 50\n    proxies:\n")
	for _, n := range names[:10] {
		fmt.Fprintf(&b, "      - %q\n", n)
	}
	b.WriteString("rules:\n")
	for i := 1; i <= 1500; i++ {
		if i%200 == 0 {
			fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,ad%d.example.com,REJECT-DROP\n", i)
		} else {
			fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,site%d.example.com,Proxy\n", i)
		}
	}
	b.WriteString("  - MATCH,Proxy\n")

	if _, fe := provider.ParseFull([]byte(b.String()), ""); fe != nil {
		t.Fatalf("ParseFull err: %v", fe)
	}
	h := fullHost(t)
	raw, _ := json.Marshal(map[string]any{"text": b.String(), "full_only": true})
	p, err := h.previewSubscription(context.Background(), raw)
	if err != nil {
		t.Fatalf("airport Clash import failed: %+v", err)
	}
	sp := p.(subscriptionPreview)
	if sp.Token == "" || len(sp.Issues) != 0 {
		t.Fatalf("unexpected preview issues=%v token=%q", sp.Issues, sp.Token)
	}
	if sp.Counts["nodes"] != 80 || sp.Counts["groups"] != 3 || sp.Counts["rules"] != 1500 {
		t.Fatalf("unexpected counts: %+v", sp.Counts)
	}
}
