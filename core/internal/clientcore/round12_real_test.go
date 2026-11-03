package clientcore

import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/provider"
	"net/url"
	"os"
	"testing"
	"time"
)

// Opt-in authorized real input. Never include URL queries, node endpoints or
// credentials in failures/reports. The core, rules and actual SOCKS path are real.
func TestR12AuthorizedResourceRoute(t *testing.T) {
	file := os.Getenv("KAT_R12_PRIVATE_SOURCE")
	if file == "" {
		t.Skip("authorized real input not supplied")
	}
	b, e := os.ReadFile(file)
	if e != nil {
		t.Fatal("private input unavailable")
	}
	h := fullHost(t)
	v, er := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": string(b)}))
	if er != nil {
		t.Fatalf("initial direct import failed: %s detail=%+v", er.Code, er.Detail)
	}
	p := v.(subscriptionPreview)
	if dir := os.Getenv("KAT_R12_PRIVATE_DIR"); dir != "" {
		os.WriteFile(dir+"/core-source.json", []byte(p.Text), 0600)
	}
	if len(p.Issues) > 0 {
		t.Fatal("real subscription conversion issues")
	}
	if _, er = h.Apply(p.Text, p.Format); er != nil {
		t.Fatal("real subscription apply failed", er.Code)
	}
	if _, er = h.Start(); er != nil {
		t.Fatal("real core start failed", er.Code)
	}
	report := map[string]any{"nodes": len(h.doc.config.Outbounds), "groups": len(h.doc.config.Groups), "rules": h.doc.config.Routing.Rules}
	// The rules contain only matcher/target names, not source URLs or credentials.
	rows := []map[string]any{}
	full, err := provider.ParseFull(b, h.doc.client.ProbeURL)
	if err != nil {
		t.Fatal("real provider parse failed")
	}
	for i, rs := range full.RuleSets {
		if i != 3 {
			continue
		}
		u, _ := url.Parse(rs.URL)
		row := map[string]any{"ordinal": i + 1, "host": u.Hostname(), "path": u.Path}
		before := h.connectionLogs.read(0, 500).NextSeq
		start := time.Now()
		_, err := h.fetchKernelAsset(context.Background(), rs.URL, 16<<20)
		row["elapsed_ms"] = time.Since(start).Milliseconds()
		if err != nil {
			row["kernel_error"] = safeFailure(context.Background(), "connect", err).Error()
		} else {
			row["kernel_success"] = true
		}
		row["connection_events"] = h.connectionLogs.read(before, 500).Entries
		row["connections"], _ = h.listConnections(rawJSON(map[string]any{"closed_limit": 30}))
		ctx := context.WithValue(context.Background(), resourceKernelKey{}, false)
		start = time.Now()
		_, err = h.fetchFull(ctx, rs.URL, nil, 16<<20)
		row["direct_elapsed_ms"] = time.Since(start).Milliseconds()
		if err != nil {
			row["direct_error"] = safeFailure(context.Background(), "connect", err).Error()
		} else {
			row["direct_success"] = true
		}
		ctx = context.WithValue(context.Background(), resourceKernelKey{}, true)
		start = time.Now()
		out, fallbackErr := h.fetchSubscriptionResource(ctx, rs.URL, nil, 16<<20)
		row["fallback_elapsed_ms"] = time.Since(start).Milliseconds()
		row["fallback_success"] = fallbackErr == nil && len(out) > 0
		if fallbackErr != nil {
			t.Fatal("authorized running resource fallback still failed")
		}
		rows = append(rows, row)
	}
	report["resources"] = rows
	data, _ := json.MarshalIndent(report, "", "  ")
	// Full report is task-private; a separate allow-list projection is delivered.
	if out := os.Getenv("KAT_R12_PRIVATE_REPORT"); out != "" {
		os.WriteFile(out, data, 0600)
	}
	t.Log("real subscription route exercised; report kept private for safe projection")
}
