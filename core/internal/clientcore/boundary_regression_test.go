package clientcore

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/provider"
	"github.com/shui1iao/Kat/internal/tunplatform"
)

func findNullSlicePaths(v any, prefix string) []string {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	var hits []string
	switch rv.Kind() {
	case reflect.Slice:
		if rv.IsNil() {
			hits = append(hits, prefix)
		} else {
			for i := 0; i < rv.Len(); i++ {
				hits = append(hits, findNullSlicePaths(rv.Index(i).Interface(), fmt.Sprintf("%s[%d]", prefix, i))...)
			}
		}
	case reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			hits = append(hits, findNullSlicePaths(rv.Index(i).Interface(), fmt.Sprintf("%s[%d]", prefix, i))...)
		}
	case reflect.Map:
		for _, k := range rv.MapKeys() {
			hits = append(hits, findNullSlicePaths(rv.MapIndex(k).Interface(), fmt.Sprintf("%s.%v", prefix, k.Interface()))...)
		}
	case reflect.Struct:
		rt := rv.Type()
		for i := 0; i < rt.NumField(); i++ {
			sf := rt.Field(i)
			if !sf.IsExported() {
				continue
			}
			jtag := sf.Tag.Get("json")
			if jtag == "-" {
				continue
			}
			parts := strings.Split(jtag, ",")
			name := parts[0]
			if name == "" {
				name = sf.Name
			}
			omitempty := false
			for _, opt := range parts[1:] {
				if opt == "omitempty" {
					omitempty = true
				}
			}
			fv := rv.Field(i)
			if sf.Anonymous && parts[0] == "" {
				hits = append(hits, findNullSlicePaths(fv.Interface(), prefix)...)
				continue
			}
			if omitempty && fv.IsZero() {
				continue
			}
			hits = append(hits, findNullSlicePaths(fv.Interface(), prefix+"."+name)...)
		}
	}
	return hits
}

func TestRegressionIPCJSONSliceSafetyAllMethods(t *testing.T) {
	h := newHost(t)
	defer h.Close()

	checkMethod := func(label, method string, params string) {
		t.Helper()
		res, rpcErr := h.Request(context.Background(), method, json.RawMessage(params))
		if rpcErr != nil {
			t.Fatalf("%s (%s) unexpected rpc error: %+v", label, method, rpcErr)
		}
		nullSlices := findNullSlicePaths(res, method)
		jb, mErr := json.Marshal(res)
		if mErr != nil {
			t.Fatalf("%s marshal failed: %v", label, mErr)
		}
		if len(nullSlices) > 0 {
			t.Fatalf("[NULL-SLICE-FOUND] in %s: paths=%v json=%s", label, nullSlices, string(jb))
		}
	}

	checkMethod("stopped/status", "status", `{}`)
	checkMethod("stopped/connections.list", "connections.list", `{}`)
	checkMethod("stopped/connections.logs", "logs.connections", `{}`)
	checkMethod("stopped/dns.logs", "logs.dns", `{}`)
	checkMethod("stopped/logs.get", "logs.get", `{}`)
	checkMethod("stopped/logs.kernel", "logs.kernel", `{}`)
	checkMethod("stopped/subscription.status", "subscription.status", `{}`)
	checkMethod("stopped/network.egress.get", "network.egress.get", "{}")
	checkMethod("stopped/resources.list", "resources.list", "{}")
	checkMethod("stopped/network.tun.status", "network.tun.status", "{}")
	checkMethod("stopped/hello", "hello", "{}")
	checkMethod("stopped/document.get", "document.get", "{}")
	checkMethod("stopped/group.filter_preview", "group.filter_preview", `{"filter":"nonexistent_pattern_xyz"}`)
	checkMethod("stopped/previewTarget_ip", "routing.previewTarget", `{"target":"1.1.1.1"}`)
	checkMethod("stopped/previewTarget_domain", "routing.previewTarget", `{"target":"example.com"}`)
	checkMethod("stopped/import.parse", "import.parse", `{"text":"socks5://1.2.3.4:1080#node1"}`)

	h.starting.Store(true)
	h.fastSnap.Store(&fastHostSnapshot{mode: "rule", httpPort: 17890, socksPort: 17891})
	h.mu.Lock()
	fastVal := h.Status()
	h.mu.Unlock()
	h.starting.Store(false)
	if ns := findNullSlicePaths(fastVal, "starting.Status"); len(ns) > 0 {
		jb, _ := json.Marshal(fastVal)
		t.Fatalf("[NULL-SLICE-FOUND] in starting.Status: %v json=%s", ns, string(jb))
	}

	if ns := findNullSlicePaths(tunplatform.SafeDiagnostic(tunplatform.Diagnostic{
		Stage:   "cleanup_gone",
		Removal: &tunplatform.RemovalObservation{Rows: nil},
	}), "SafeDiagnostic"); len(ns) > 0 {
		t.Fatalf("[NULL-SLICE-FOUND] in SafeDiagnostic: %v", ns)
	}

	if _, err := h.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer h.Stop()
	checkMethod("running/status", "status", `{}`)
	checkMethod("running/connections.list", "connections.list", `{}`)
	checkMethod("running/dns.cache", "dns.cache.list", `{}`)
	checkMethod("running/previewTarget_domain", "routing.previewTarget", `{"target":"example.com"}`)
}

func TestRegressionGroupDepthConsistentAcrossDocumentPreviewAndStart(t *testing.T) {
	h := newHost(t)
	defer h.Close()

	buildChainDoc := func(layers int) (string, kernel.Config) {
		chain := make([]any, layers)
		kGroups := make([]kernel.GroupConfig, layers)
		for i := 0; i < layers; i++ {
			next := "p"
			if i+1 < layers {
				next = fmt.Sprintf("G%d", i+1)
			}
			name := fmt.Sprintf("G%d", i)
			chain[i] = map[string]any{
				"name":     name,
				"type":     "select",
				"members":  []any{next},
				"selected": next,
			}
			kGroups[i] = kernel.GroupConfig{
				Name:     name,
				Type:     "select",
				Members:  []string{next},
				Selected: next,
			}
		}
		k := settingsKernel(t)
		k["groups"] = chain
		k["routing"] = map[string]any{"final": "G0", "rules": []any{}}
		docText := settingsText(t, fixture(t, k), nil)

		rawCfg := kernel.Config{
			Inbounds:  []kernel.Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0", Name: "in"}},
			Outbounds: []kernel.OutboundConfig{{Name: "p", Type: "socks5", Server: "127.0.0.1", Port: 1080}},
			Groups:    kGroups,
			Routing:   &kernel.RoutingOptions{Final: "G0"},
		}
		return docText, rawCfg
	}

	// 1. Exactly MaxGroupDepth (8) layers -> must succeed in document.validate, document.set, stopped preview, Start, and running preview!
	doc8, _ := buildChainDoc(group.MaxGroupDepth)
	if _, err := h.validateDocument(doc8); err != nil {
		t.Fatalf("expected %d-layer group chain to pass validateDocument, got %v", group.MaxGroupDepth, err)
	}
	if _, err := h.Apply(doc8); err != nil {
		t.Fatalf("expected %d-layer group chain to pass Apply, got %v", group.MaxGroupDepth, err)
	}
	if _, rpcErr := h.Request(context.Background(), "routing.previewTarget", json.RawMessage(`{"target":"example.com"}`)); rpcErr != nil {
		t.Fatalf("expected %d-layer stopped previewTarget to succeed, got %+v", group.MaxGroupDepth, rpcErr)
	}
	if _, err := h.Start(); err != nil {
		t.Fatalf("expected %d-layer Start to succeed, got %v", group.MaxGroupDepth, err)
	}
	if _, rpcErr := h.Request(context.Background(), "routing.previewTarget", json.RawMessage(`{"target":"example.com"}`)); rpcErr != nil {
		t.Fatalf("expected %d-layer running previewTarget to succeed, got %+v", group.MaxGroupDepth, rpcErr)
	}
	_, _ = h.Stop()

	// 2. 100-layer chain (> MaxGroupDepth=8) -> must be consistently rejected by document.validate, document.set, PreviewStoppedTarget, and kernel.New/Start!
	doc100, cfg100 := buildChainDoc(100)
	if _, err := h.validateDocument(doc100); err == nil {
		t.Fatal("100-layer group chain must be rejected by document.validate")
	}
	if _, rpcErr := h.Request(context.Background(), "document.set", rawJSON(map[string]any{"text": doc100, "format": "json"})); rpcErr == nil {
		t.Fatal("100-layer group chain must be rejected by document.set")
	}
	if _, err := kernel.PreviewStoppedTarget(context.Background(), cfg100, cfg100.Routing, "example.com"); err == nil {
		t.Fatal("100-layer group chain must be rejected by PreviewStoppedTarget")
	}
	if err := cfg100.Validate(); err == nil {
		t.Fatal("100-layer group chain must be rejected by kernel.Config.Validate")
	}
	if _, err := kernel.Start(cfg100); err == nil {
		t.Fatal("100-layer group chain must be rejected by kernel.Start")
	}
}

type infiniteZeroStream struct {
	rem int64
}

func (s *infiniteZeroStream) Read(p []byte) (int, error) {
	if s.rem <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > s.rem {
		n = int(s.rem)
	}
	clear(p[:n])
	s.rem -= int64(n)
	return n, nil
}
func (s *infiniteZeroStream) Close() error { return nil }

func TestRegressionSubscriptionSSRFAndDecompressionBounds(t *testing.T) {
	h := fullHost(t)
	for _, badURL := range []string{
		"http://example.com/sub",
		"https://127.0.0.1/sub",
		"https://[::1]/sub",
		"https://localhost/sub",
		"https://169.254.169.254/latest/meta-data/",
		"https://192.168.1.1/sub",
		"https://user:pass@example.com/sub",
	} {
		if _, rpcErr := h.previewSubscription(context.Background(), rawJSON(map[string]any{"url": badURL, "name": "ssrf"})); rpcErr == nil {
			t.Fatalf("expected SSRF/insecure URL %q to be rejected", badURL)
		}
	}

	subCtx := context.WithValue(context.Background(), subscriptionHeadersKey{}, &subscriptionHeaders{})
	stream200M := &infiniteZeroStream{rem: 200 << 20}
	_, err := fetchImportBounded(subCtx, "https://sub.example.com/huge", nil, func(*http.Transport) http.RoundTripper {
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: stream200M, Request: req}, nil
		})
	}, provider.MaxSize)
	if err == nil {
		t.Fatal("expected 200MiB stream to fail size_limit")
	}
	if consumed := (200 << 20) - stream200M.rem; consumed > provider.MaxSize+64*1024 {
		t.Fatalf("200MiB stream read too much before aborting: %d bytes", consumed)
	}

	var gzBuf bytes.Buffer
	gzw, _ := gzip.NewWriterLevel(&gzBuf, gzip.BestCompression)
	chunk := make([]byte, 64<<10)
	for i := 0; i < (32<<20)/(64<<10); i++ {
		_, _ = gzw.Write(chunk)
	}
	_ = gzw.Close()
	_, err = fetchImportBounded(subCtx, "https://sub.example.com/gzbomb", nil, func(*http.Transport) http.RoundTripper {
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			gr, gErr := gzip.NewReader(bytes.NewReader(gzBuf.Bytes()))
			if gErr != nil {
				return nil, gErr
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: gr, Uncompressed: true, Request: req}, nil
		})
	}, provider.MaxSize)
	if err == nil {
		t.Fatal("expected gzip bomb to fail size_limit")
	}
	_ = time.Second
}
