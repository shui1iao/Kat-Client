package clientcore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/kernel"
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
	Capacity int                  `json:"capacity"`
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
	e.Addresses = append([]string(nil), e.Addresses...)
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
		e.Addresses = append([]string(nil), e.Addresses...)
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
