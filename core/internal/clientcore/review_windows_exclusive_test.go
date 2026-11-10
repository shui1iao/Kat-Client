package clientcore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/route"
)

func buildLargeClassicalRuleSet(lines int) []byte {
	var buf bytes.Buffer
	for i := 0; i < lines; i++ {
		if i == lines/2 {
			buf.WriteString("GEOIP,CN\n")
		} else if i == lines-1 {
			buf.WriteString("IP-ASN,13335,no-resolve\n")
		} else {
			fmt.Fprintf(&buf, "DOMAIN-SUFFIX,example-%d.org\n", i)
		}
	}
	return buf.Bytes()
}

// BenchmarkReviewWindowsSubscriptionSetNeeds measures memory allocations and throughput
// when scanning a large classical rule-set for GeoIP/ASN database requirements.
func BenchmarkReviewWindowsSubscriptionSetNeeds(b *testing.B) {
	raw := buildLargeClassicalRuleSet(20000)
	opt := route.RuleSetOptions{Format: "classical", Behavior: "classical"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, a, err := subscriptionSetNeeds(opt, raw)
		if err != nil || !c || !a {
			b.Fatalf("unexpected result: c=%v a=%v err=%v", c, a, err)
		}
	}
}

// BenchmarkReviewWindowsSubscriptionSetIssues measures formatting 200 rule-set validation
// issues (where regex compilation previously occurred on every loop iteration).
func BenchmarkReviewWindowsSubscriptionSetIssues(b *testing.B) {
	issues := make([]route.SubscriptionSetIssue, 200)
	for i := range issues {
		issues[i] = route.SubscriptionSetIssue{
			Resource:   "rules",
			Entry:      i + 1,
			Line:       i + 2,
			RuleType:   "GEOIP",
			Code:       "missing_dependency",
			Dependency: "geoip",
		}
	}
	validationErr := &route.SubscriptionSetValidationError{Issues: issues}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := subscriptionSetIssues(1, validationErr)
		if len(out) != 200 {
			b.Fatalf("unexpected issues count: %d", len(out))
		}
	}
}

// BenchmarkReviewWindowsHTTPBridgeConnectConnContext measures per-connection allocation
// overhead in httpBridge.ConnContext + ConnState for non-HTTP-RoundTrip connections
// (such as HTTPS CONNECT tunnels and OPTIONS * health checks).
func BenchmarkReviewWindowsHTTPBridgeConnectConnContext(b *testing.B) {
	bridge, err := newHTTPBridge(0, 1080)
	if err != nil {
		b.Fatal(err)
	}
	defer bridge.close()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	baseCtx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := bridge.server.ConnContext(baseCtx, c1)
		if ctx == nil {
			b.Fatal("nil context")
		}
		bridge.server.ConnState(c1, http.StateClosed)
	}
}

// BenchmarkReviewWindowsCandidateRetention measures retained fullCandidates entries
// and heap bytes held by Host after repeated unapplied new subscription previews
// followed by a document apply that invalidates their base.
func BenchmarkReviewWindowsCandidateRetention(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		h, err := Open(b.TempDir())
		if err != nil {
			b.Fatal(err)
		}
		h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
			return []byte("payload: [example.org]"), nil
		}
		pad := strings.Repeat("# padding comment line for large subscription preview\n", 1000)
		b.StartTimer()

		for j := 0; j < 8; j++ {
			fixture := fmt.Sprintf("%s%srule-providers:\n  list%d:\n    type: http\n    behavior: domain\n    format: yaml\n    url: https://example.org/rules-%d\n", fullFixture, pad, j, j)
			_, err := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": fixture}))
			if err != nil {
				b.Fatal(err)
			}
		}
		// Apply the last preview; prior 7 unapplied previews have a stale Base (initialDocument).
		lastText := h.fullPending.Text
		lastFormat := h.fullPending.Format
		if _, err := h.Apply(lastText, lastFormat); err != nil {
			b.Fatal(err)
		}
		h.mu.Lock()
		retained := len(h.fullCandidates)
		var retainedTextBytes int
		for _, p := range h.fullCandidates {
			retainedTextBytes += len(p.Base) + len(p.Text)
		}
		h.mu.Unlock()
		b.ReportMetric(float64(retained), "retained_candidates")
		b.ReportMetric(float64(retainedTextBytes), "retained_bytes")

		b.StopTimer()
		_ = h.Close()
	}
}

func TestReviewWindowsCandidateCleanupAndExpiry(t *testing.T) {
	h := fullHost(t)
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) (b []byte, err error) {
		return []byte("payload: [example.org]"), nil
	}

	// 1. Create 10 concurrent valid candidates (> 8) on the same base document.
	// None of the valid candidates may be evicted before base changes or 30m expiry.
	const total = 10
	previews := make([]*subscriptionPreview, total)
	dirs := make([]string, total)
	for i := 0; i < total; i++ {
		h.fullFetch = func(_ context.Context, u string, _ *clientegress.Policy, _ int64) ([]byte, error) {
			return []byte(fmt.Sprintf("payload: [example-%d.org]\n# %s\n", i, u)), nil
		}
		fixture := fmt.Sprintf("%srule-providers:\n  list%d:\n    type: http\n    behavior: domain\n    format: yaml\n    url: https://example.org/rules-%d\n", fullFixture, i, i)
		previews[i] = fullPreview(t, h, fixture, "")
		dirs[i] = h.fullPending.Dir
		if dirs[i] == "" {
			t.Fatalf("expected staged resource dir for candidate %d", i)
		}
	}
	if len(h.fullCandidates) != total {
		t.Fatalf("expected all %d valid concurrent candidates to be retained, got %d", total, len(h.fullCandidates))
	}
	for i, d := range dirs {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("candidate %d dir should exist before apply: %v", i, err)
		}
	}

	// Verify that pruneStaleCandidatesLocked preserves a directory if it has acceptedResourceMarker:
	// create an expired candidate whose Dir has acceptedResourceMarker, then trigger pruneStaleCandidatesLocked
	// via another preview on the same base (before Apply runs collectResourceVersionsLocked).
	protectedDir := filepath.Join(h.workspace, "subscription-"+strings.Repeat("a", 64))
	if err := os.Mkdir(protectedDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(protectedDir, acceptedResourceMarker), []byte("Kat accepted resources\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.fullCandidates["expired-marked"] = &subscriptionPending{
		Token:   "tok-expired",
		Base:    h.doc.text,
		Format:  h.doc.format,
		Text:    "expired-candidate-text",
		Dir:     protectedDir,
		Created: time.Now().Add(-31 * time.Minute),
	}
	h.pruneStaleCandidatesLocked("")
	_, stillPresent := h.fullCandidates["expired-marked"]
	h.mu.Unlock()
	if stillPresent {
		t.Fatal("expired candidate should have been pruned from fullCandidates")
	}
	if _, err := os.Stat(protectedDir); err != nil {
		t.Fatalf("pruneStaleCandidatesLocked must NOT delete a directory with acceptedResourceMarker: %v", err)
	}
	_ = os.RemoveAll(protectedDir)

	// Apply the earliest candidate (previews[0]) to prove even the oldest (>8) candidate
	// was NOT evicted and remains fully usable.
	if _, err := h.Apply(previews[0].Text, previews[0].Format); err != nil {
		t.Fatalf("apply earliest candidate previews[0] failed: %v", err)
	}

	// Now that previews[0] has been applied, h.doc.text changed; all other 9 candidates
	// have a stale Base and must have been pruned from h.fullCandidates.
	h.mu.Lock()
	rem := len(h.fullCandidates)
	h.mu.Unlock()
	if rem != 0 {
		t.Fatalf("expected 0 retained candidates after base changed, got %d", rem)
	}

	// Applying any stale candidate must return candidate_expired.
	for i := 1; i < total; i++ {
		if _, err := h.Apply(previews[i].Text, previews[i].Format); err == nil || err.Code != "candidate_expired" {
			t.Fatalf("expected candidate_expired for stale candidate %d, got %+v", i, err)
		}
	}

	// Accepted dir (dirs[0]) must remain intact; unaccepted owned dirs (dirs[1..9]) must be removed.
	if _, err := os.Stat(dirs[0]); err != nil {
		t.Fatalf("accepted dir[0] must exist: %v", err)
	}
	for i := 1; i < total; i++ {
		if _, err := os.Stat(dirs[i]); !os.IsNotExist(err) {
			t.Fatalf("expected unaccepted stale candidate dir[%d] to be removed, stat err=%v", i, err)
		}
	}
}

func TestReviewWindowsRetiredBridgeLifecycleAndTailClear(t *testing.T) {
	// Start local HTTP target for CONNECT and HTTP body tests.
	bodyEntered := make(chan struct{})
	releaseBody := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(200)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			close(bodyEntered)
			<-releaseBody
			_, _ = w.Write([]byte("stream-body-complete"))
			return
		}
		_, _ = w.Write([]byte("tunnel-ok"))
	}))
	defer target.Close()

	h := newHost(t)
	baseText := fixture(t, map[string]any{
		"dns":      map[string]any{"server": "system"},
		"security": map[string]any{"allow_loopback": true},
	})
	withPorts := func(hp, sp int) string {
		var raw map[string]any
		_ = json.Unmarshal([]byte(baseText), &raw)
		raw["client"].(map[string]any)["http_port"] = hp
		raw["client"].(map[string]any)["socks_port"] = sp
		b, _ := json.Marshal(raw)
		return string(b)
	}
	hp0, sp0 := freePort(t), freePort(t)
	for hp0 == sp0 {
		hp0, sp0 = freePort(t), freePort(t)
	}
	if _, e := h.Apply(withPorts(hp0, sp0)); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	bridge0 := h.bridge

	// 1. Open a connection that is accepted by bridge0 BEFORE reload, but has NOT
	// sent its request headers yet (accepted-but-not-yet-in-ServeHTTP).
	preConn, err := net.Dial("tcp4", portAddress(hp0))
	if err != nil {
		t.Fatal(err)
	}
	defer preConn.Close()
	_ = preConn.SetDeadline(time.Now().Add(5 * time.Second))
	// Wait until bridge0's ConnContext has registered preConn.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		bridge0.mu.Lock()
		c := bridge0.conns
		bridge0.mu.Unlock()
		if c >= 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	// 2. Open an active HTTP body request on bridge0 that stays mid-body across reload.
	httpConn, err := net.Dial("tcp4", portAddress(hp0))
	if err != nil {
		t.Fatal(err)
	}
	defer httpConn.Close()
	_ = httpConn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(httpConn, "GET %s/stream HTTP/1.1\r\nHost: %s\r\n\r\n", target.URL, strings.TrimPrefix(target.URL, "http://"))
	<-bodyEntered

	// 3. Open an active CONNECT tunnel on bridge0 that stays open across reload.
	connectConn, err := net.Dial("tcp4", portAddress(hp0))
	if err != nil {
		t.Fatal(err)
	}
	defer connectConn.Close()
	_ = connectConn.SetDeadline(time.Now().Add(5 * time.Second))
	dst := strings.TrimPrefix(target.URL, "http://")
	fmt.Fprintf(connectConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dst, dst)
	connectBR := bufio.NewReader(connectConn)
	resp, err := http.ReadResponse(connectBR, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %v %+v", err, resp)
	}

	// 4. Reload with new HTTPPort hp1 -> bridge0 is retired.
	hp1 := freePort(t)
	for hp1 == hp0 || hp1 == sp0 {
		hp1 = freePort(t)
	}
	if _, e := h.Apply(withPorts(hp1, sp0)); e != nil {
		t.Fatal(e)
	}
	if bridge0.isClosed() {
		t.Fatal("retired bridge0 must NOT close while accepted/active flows are still open")
	}

	// 5. Now send OPTIONS * on preConn (which was accepted before retire, but enters ServeHTTP after retire).
	fmt.Fprintf(preConn, "OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n")
	preBR := bufio.NewReader(preConn)
	preResp, err := http.ReadResponse(preBR, &http.Request{Method: "OPTIONS"})
	if err != nil || preResp.StatusCode != 204 {
		t.Fatalf("accepted-before-retire connection failed ServeHTTP after retire: err=%v resp=%+v", err, preResp)
	}
	_ = preConn.Close()

	// Bridge0 still has httpConn (mid-body) and connectConn (hijacked tunnel), so it must still not be closed.
	if bridge0.isClosed() {
		t.Fatal("bridge0 closed while HTTP body and CONNECT tunnel were still active")
	}

	// 6. Finish HTTP body stream and verify client receives full body.
	close(releaseBody)
	httpBR := bufio.NewReader(httpConn)
	httpResp, err := http.ReadResponse(httpBR, nil)
	if err != nil {
		t.Fatalf("HTTP body stream failed after reload: %v", err)
	}
	bodyBytes, err := io.ReadAll(httpResp.Body)
	_ = httpResp.Body.Close()
	_ = httpConn.Close()
	if err != nil || string(bodyBytes) != "stream-body-complete" {
		t.Fatalf("unexpected HTTP body after reload: %q err=%v", string(bodyBytes), err)
	}

	// Bridge0 still has connectConn (hijacked tunnel), so it must still not be closed.
	if bridge0.isClosed() {
		t.Fatal("bridge0 closed while hijacked CONNECT tunnel was still active")
	}

	// 7. Use the CONNECT tunnel and then close it.
	fmt.Fprintf(connectConn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", dst)
	tunResp, err := http.ReadResponse(connectBR, nil)
	if err != nil {
		t.Fatalf("CONNECT tunnel request failed: %v", err)
	}
	tunBody, _ := io.ReadAll(tunResp.Body)
	_ = tunResp.Body.Close()
	_ = connectConn.Close()
	if string(tunBody) != "tunnel-ok" {
		t.Fatalf("unexpected tunnel body: %q", string(tunBody))
	}

	// 8. Now that all accepted connections, HTTP bodies, and CONNECT tunnels on bridge0 have ended,
	// bridge0 must transition to closed automatically.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !bridge0.isClosed() {
		runtime.Gosched()
		time.Sleep(5 * time.Millisecond)
	}
	if !bridge0.isClosed() || bridge0.ctx.Err() == nil {
		t.Fatal("bridge0 did not close after all connections and tunnels finished")
	}

	// 9. Retire a second bridge (bridge1) and verify retiredBridges compaction
	// and backing-array tail slot nil-clearing.
	bridge1 := h.bridge
	hold1, err := net.Dial("tcp4", portAddress(hp1))
	if err != nil {
		t.Fatal(err)
	}
	defer hold1.Close()
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		bridge1.mu.Lock()
		c := bridge1.conns
		bridge1.mu.Unlock()
		if c >= 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	hp2 := freePort(t)
	for hp2 == hp1 || hp2 == hp0 || hp2 == sp0 {
		hp2 = freePort(t)
	}
	dummyClosed, err := newHTTPBridge(0, sp0)
	if err != nil {
		t.Fatal(err)
	}
	dummyClosed.close()
	h.mu.Lock()
	h.retiredBridges = append(h.retiredBridges, dummyClosed)
	h.mu.Unlock()

	if _, e := h.Apply(withPorts(hp2, sp0)); e != nil {
		t.Fatal(e)
	}
	h.mu.Lock()
	if len(h.retiredBridges) != 1 || h.retiredBridges[0] != bridge1 {
		h.mu.Unlock()
		t.Fatalf("expected retiredBridges to have only bridge1 (len=1), got len=%d", len(h.retiredBridges))
	}
	backing := h.retiredBridges[:cap(h.retiredBridges)]
	for i := 1; i < len(backing); i++ {
		if backing[i] != nil {
			h.mu.Unlock()
			t.Fatalf("retiredBridges backing array tail slot %d was not cleared to nil: %v", i, backing[i])
		}
	}
	h.mu.Unlock()
	_ = hold1.Close()
}
