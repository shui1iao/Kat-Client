package clientcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/kernel"
	"gopkg.in/yaml.v3"
	"sync"
)

type DNSEntry struct {
	Seq uint64 `json:"seq"`
	kernel.DNSEvent
}

type DNSLogsReply struct {
	Instance uint64     `json:"instance"`
	Entries  []DNSEntry `json:"entries"`
	NextSeq  uint64     `json:"next_seq"`
	Dropped  uint64     `json:"dropped"`
}

type DNSCacheListReply struct {
	Capacity int                   `json:"capacity"`
	Entries  []kernel.DNSCacheItem `json:"entries"`
}

type dnsRing struct {
	mu           sync.Mutex
	entries      [logCapacity]DNSEntry
	seq, dropped uint64
	size         int
}

func (r *dnsRing) record(e kernel.DNSEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seq == maxLogSeq {
		return
	}
	r.seq++
	e.Addresses = append([]string{}, e.Addresses...)
	r.entries[(r.seq-1)%logCapacity] = DNSEntry{r.seq, e}
	if r.size < logCapacity {
		r.size++
	} else {
		r.dropped++
	}
}

func (r *dnsRing) read(after uint64, limit int) DNSLogsReply {
	r.mu.Lock()
	defer r.mu.Unlock()
	if after > r.seq {
		after = 0
	}
	out := DNSLogsReply{Instance: logInstance, Entries: []DNSEntry{}, NextSeq: after, Dropped: r.dropped}
	if after >= r.seq {
		return out
	}
	first := r.seq - uint64(r.size) + 1
	if after >= first {
		first = after + 1
	}
	for seq := first; seq <= r.seq && len(out.Entries) < limit; seq++ {
		e := r.entries[(seq-1)%logCapacity]
		e.Addresses = append([]string{}, e.Addresses...)
		out.Entries = append(out.Entries, e)
		out.NextSeq = seq
	}
	return out
}

func (h *Host) getDNSLogs(raw json.RawMessage) (any, *Error) {
	var p struct {
		Instance uint64          `json:"instance,omitempty"`
		After    json.RawMessage `json:"after"`
		Limit    json.RawMessage `json:"limit"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	var after uint64
	limit := 200
	if p.After != nil && (string(p.After) == "null" || json.Unmarshal(p.After, &after) != nil || after > maxLogSeq) {
		return nil, fail("invalid_params", "params.after", "Expected nonnegative safe integer")
	}
	if e := boundedLimit(p.Limit, &limit, "params.limit"); e != nil {
		return nil, e
	}
	if p.Instance != 0 && p.Instance != logInstance {
		after = 0
	}
	return h.dnsLogs.read(after, limit), nil
}

func (h *Host) listDNSCache(raw json.RawMessage) (any, *Error) {
	if e := decodeParams(raw, &struct{}{}); e != nil {
		return nil, e
	}
	h.mu.Lock()
	s := h.server
	h.mu.Unlock()
	if s == nil {
		return nil, fail("core_not_running", "runtime", "Core is stopped")
	}
	items, capVal, e := s.ListDNSCache()
	if e != nil {
		return nil, fail("core_not_running", "runtime", "Core is stopped")
	}
	if items == nil {
		items = []kernel.DNSCacheItem{}
	}
	return DNSCacheListReply{Capacity: capVal, Entries: items}, nil
}

func (h *Host) queryDNS(ctx context.Context, raw json.RawMessage) (any, *Error) {
	var p struct {
		Name string          `json:"name"`
		Type json.RawMessage `json:"type"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	typ := "both"
	if p.Type != nil && (string(p.Type) == "null" || json.Unmarshal(p.Type, &typ) != nil || typ != "A" && typ != "AAAA" && typ != "both") {
		return nil, fail("invalid_params", "params.type", "Expected A, AAAA or both")
	}
	if p.Name == "" {
		return nil, fail("invalid_name", "params.name", "Valid DNS name required")
	}
	h.mu.Lock()
	s := h.server
	if s == nil {
		h.mu.Unlock()
		return nil, fail("core_not_running", "runtime", "Core is stopped")
	}
	qctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(h.probeCtx, cancel)
	h.probeWG.Add(1)
	h.mu.Unlock()
	result, err := s.QueryDNS(qctx, p.Name, typ)
	stop()
	cancel()
	h.probeWG.Done()
	if errors.Is(err, kernel.ErrDNSInvalidName) {
		return nil, fail("invalid_name", "params.name", "Valid DNS name required")
	}
	if errors.Is(err, kernel.ErrCoreNotRunning) {
		return nil, fail("core_not_running", "runtime", "Core is stopped")
	}
	if err != nil {
		return nil, fail("dns_failed", "params.name", "DNS chain did not return an answer")
	}
	return result, nil
}

const advancedDNSMessage = "此配置包含已停用的高级 DNS，请选择系统 DNS 或自定义 DNS 后保存"

func advancedDNSFields(client, kernel map[string]json.RawMessage) bool {
	var dns map[string]json.RawMessage
	_ = json.Unmarshal(kernel["dns"], &dns)
	// Presence is deliberate: empty/latent retired structures still must not
	// become a future effective capability via another input path.
	for _, k := range []string{"hosts", "rules", "nameserver-policy"} {
		if _, ok := dns[k]; ok {
			return true
		}
	}
	if b, ok := client["tun_dns"]; ok && !bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		var fields map[string]json.RawMessage
		if json.Unmarshal(b, &fields) == nil {
			for _, k := range []string{"remote", "fake_ip", "fake_ip_filter"} {
				if _, ok := fields[k]; ok {
					return true
				}
			}
		}
	}
	return false
}
func sanitizeDNSProjection(kernel map[string]json.RawMessage) {
	var dns map[string]json.RawMessage
	_ = json.Unmarshal(kernel["dns"], &dns)
	if dns == nil {
		dns = map[string]json.RawMessage{}
	}
	for _, k := range []string{"hosts", "rules", "nameserver-policy"} {
		delete(dns, k)
	}
	kernel["dns"], _ = json.Marshal(dns)
}
func (d document) dnsEnableError() *Error {
	if d.advancedDNS {
		return fail("advanced_dns_retired", "kernel.dns", advancedDNSMessage)
	}
	return nil
}

// Object order is normally immaterial, but mihomo nameserver-policy uses
// declaration order for first-match semantics. yamlJSON intentionally builds
// ordinary Go maps, so retain this one ordered object's source-node order in
// the runtime projection. The authoritative YAML text is not rewritten.
func preserveYAMLDNSPolicy(text string, kernel map[string]json.RawMessage) error {
	if len(kernel["dns"]) == 0 || !bytes.Contains(kernel["dns"], []byte(`"nameserver-policy"`)) {
		return nil
	}
	var tree yaml.Node
	if yaml.Unmarshal([]byte(text), &tree) != nil || len(tree.Content) != 1 {
		return errYAML
	}
	field := func(node *yaml.Node, key string) *yaml.Node {
		if node == nil || node.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				return node.Content[i+1]
			}
		}
		return nil
	}
	node := field(field(field(tree.Content[0], "kernel"), "dns"), "nameserver-policy")
	if node == nil {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return errYAML
	}
	var policy bytes.Buffer
	policy.WriteByte('{')
	for i := 0; i+1 < len(node.Content); i += 2 {
		if i > 0 {
			policy.WriteByte(',')
		}
		key, _ := json.Marshal(node.Content[i].Value)
		budget := maxYAMLNodes
		value, e := yamlValue(node.Content[i+1], 0, &budget)
		if e != nil {
			return e
		}
		encoded, e := json.Marshal(value)
		if e != nil {
			return e
		}
		policy.Write(key)
		policy.WriteByte(':')
		policy.Write(encoded)
	}
	policy.WriteByte('}')
	var dns map[string]json.RawMessage
	if json.Unmarshal(kernel["dns"], &dns) != nil {
		return errYAML
	}
	dns["nameserver-policy"] = policy.Bytes()
	kernel["dns"] = rawJSON(dns)
	return nil
}

func validateTunDNS(raw json.RawMessage) *Error {
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if b, ok := fields["tun_dns"]; ok {
		if string(b) == "null" {
			return fail("invalid_document", "client.tun_dns", "Expected object")
		}
		var o kernel.ClientDNSOptions
		if json.Unmarshal(b, &o) != nil {
			return fail("invalid_document", "client.tun_dns", "Invalid TUN DNS policy")
		}
	}
	return nil
}
