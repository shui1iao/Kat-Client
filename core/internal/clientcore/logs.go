package clientcore

import (
	"encoding/json"
	"github.com/shui1iao/Kat/internal/outbound"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/shui1iao/Kat/internal/kernel"
)

var logInstance = uint64(time.Now().UnixMicro()) % maxLogSeq

const logCapacity = 2000
const maxLogSeq = 9007199254740991 // exact JavaScript integer

type EventContext struct {
	Schema      uint32  `json:"schema"`
	Version     string  `json:"version"`
	Instance    uint64  `json:"instance"`
	Component   string  `json:"component"`
	Operation   string  `json:"operation"`
	OperationID uint64  `json:"operation_id"`
	Phase       string  `json:"phase"`
	Generation  uint64  `json:"generation"`
	Revision    uint64  `json:"revision"`
	Outcome     string  `json:"outcome"`
	Domain      string  `json:"domain"`
	ElapsedMS   uint64  `json:"elapsed_ms"`
	PrimaryID   *uint64 `json:"primary_id,omitempty"`
	Dropped     uint64  `json:"dropped"`
	Suppressed  uint64  `json:"suppressed"`
}
type LogEntry struct {
	Runtime *outbound.Diagnostic `json:"runtime,omitempty"`
	Meta    *EventContext        `json:"meta,omitempty"`
	Seq     uint64               `json:"seq"`
	Time    string               `json:"time"`
	Level   string               `json:"level"`
	Event   string               `json:"event"`
	Code    string               `json:"code,omitempty"`
	Group   string               `json:"group,omitempty"`
	Reason  string               `json:"reason,omitempty"`
	Rule    uint32               `json:"rule,omitempty"`
	Cause   string               `json:"cause,omitempty"`
	Win32   uint32               `json:"win32,omitempty"`
}
type LogsReply struct {
	Instance uint64     `json:"instance"`
	Entries  []LogEntry `json:"entries"`
	NextSeq  uint64     `json:"next_seq"`
	Dropped  uint64     `json:"dropped"`
}

// One ring per Host/process, not per kernel generation. Stop/start does not
// insert entries or reset the cursor; a new process starts empty.
type logRing struct {
	diagnosticDropped atomic.Uint64
	gate              map[string]struct {
		at         time.Time
		suppressed uint64
	}
	mu      sync.Mutex
	entries [logCapacity]LogEntry
	seq     uint64
	size    int
	dropped uint64
}

func (r *logRing) record(e kernel.ClientLogEvent) { r.recordIcon(e, "") }
func (r *logRing) recordIcon(e kernel.ClientLogEvent, name string) {
	if len(name) > 64 || strings.ContainsAny(name, "/?#:@=\\&") || strings.ContainsFunc(name, unicode.IsControl) {
		name = ""
	}
	// Defense in depth: even the typed hook cannot store unbounded/free data.
	if e.Event == "process_attribution_failed" || e.Event == "process_rule_skipped" {
		if !kernel.ValidAttributionLog(e) || name != "" {
			return
		}
	} else if e.Reason != "" || e.Rule != 0 || e.Cause != "" || e.Win32 != 0 {
		return
	}
	if len(e.Event) == 0 || len(e.Event) > 64 || len(e.Code) > 64 {
		return
	}
	switch e.Level {
	case "debug", "info", "warn", "error":
	default:
		return
	}
	if e.Diagnostic != nil {
		if e.Event != "runtime.observation" || !e.Diagnostic.Valid() || name != "" {
			return
		}
		if d := e.Diagnostic; d.Stage == "http_bridge" || d.Stage == "relay" || d.Stage == "connect" || strings.HasPrefix(d.Stage, "dns_") || d.Category == "nodata" || d.Category == "nxdomain" || d.Category == "canceled" || d.Category == "closed" || (d.Category == "os_error" && d.Native != nil && (*d.Native == 10053 || *d.Native == 10054)) {
			return
		}
		if !r.mu.TryLock() {
			r.diagnosticDropped.Add(1)
			return
		}
		if r.gate == nil {
			r.gate = make(map[string]struct {
				at         time.Time
				suppressed uint64
			})
		}
		key := e.Diagnostic.Stage + ":" + e.Diagnostic.Category + ":" + e.Diagnostic.Protocol + ":" + e.Diagnostic.Direction + ":" + e.Diagnostic.Action + ":" + e.Diagnostic.Trigger
		g := r.gate[key]
		window := 10 * time.Second
		if e.Diagnostic.Category == "ok" {
			window = 30 * time.Second
		}
		if !g.at.IsZero() && time.Since(g.at) < window {
			g.suppressed++
			r.gate[key] = g
			r.mu.Unlock()
			return
		}
		if len(r.gate) >= 128 {
			for k := range r.gate {
				delete(r.gate, k)
				break
			}
		}
		e.Suppressed = g.suppressed
		r.gate[key] = struct {
			at         time.Time
			suppressed uint64
		}{at: time.Now()}
	} else {
		r.mu.Lock()
	}
	defer r.mu.Unlock()
	if r.seq == maxLogSeq {
		return
	}
	r.seq++
	outcome, domain, operation := "success", "control", "diagnostics.collect"
	if e.Event == "process_rule_skipped" {
		operation, domain, outcome = "route.decide", "routing", "skipped"
	}
	if e.Diagnostic != nil {
		operation, domain = "diagnostics.collect", "transport"
		if e.Diagnostic.Category != "ok" {
			outcome = "failure"
		}
	}
	if e.Level == "error" || e.Event == "failure" || strings.HasSuffix(e.Event, "_failed") {
		outcome = "failure"
	}
	// An already-closed own cleanup is an observed no-op, not a new flow
	// failure. Keep the real closed category/native result; never suppress resets.
	if d := e.Diagnostic; d != nil && d.Stage == "http_bridge" && d.Category == "closed" && (d.Action == "close_end" || d.Action == "half_close_end") {
		outcome = "skipped"
	}
	if strings.HasPrefix(e.Event, "egress_") {
		operation, domain = "tun.revision", "control"
		if e.Event == "egress_waiting" {
			outcome = "waiting"
		}
	}
	r.entries[(r.seq-1)%logCapacity] = LogEntry{Meta: &EventContext{Schema: 1, Version: kernel.Version, Instance: logInstance, Component: "core", Operation: operation, OperationID: r.seq, Phase: "complete", Generation: e.Generation, Revision: e.Revision, Outcome: outcome, Domain: domain, ElapsedMS: e.ElapsedMS, Dropped: r.dropped + r.diagnosticDropped.Load(), Suppressed: e.Suppressed}, Runtime: e.Diagnostic, Seq: r.seq, Time: e.Time.UTC().Format(time.RFC3339Nano), Level: e.Level, Event: e.Event, Code: e.Code, Group: name, Reason: e.Reason, Rule: e.Rule, Cause: e.Cause, Win32: e.Win32}
	if r.size < logCapacity {
		r.size++
	} else {
		r.dropped++
	}
}
func (r *logRing) read(after uint64, limit int) LogsReply {
	r.mu.Lock()
	defer r.mu.Unlock()
	if after > r.seq {
		after = 0
	}
	out := LogsReply{Instance: logInstance, Entries: []LogEntry{}, NextSeq: after, Dropped: r.dropped + r.diagnosticDropped.Load()}
	first := r.seq - uint64(r.size) + 1
	if after >= r.seq {
		return out
	}
	if after >= first {
		first = after + 1
	}
	for seq := first; seq <= r.seq && len(out.Entries) < limit; seq++ {
		out.Entries = append(out.Entries, r.entries[(seq-1)%logCapacity])
		out.NextSeq = seq
	}
	return out
}
func (h *Host) runtimeConfig(c kernel.Config) kernel.Config {
	c = h.withEgress(c)
	c.SetClientLogSink(h.logs.record)
	c.SetConnectionSink(h.connectionLogs.record)
	c.SetKernelLogSink(h.kernelLogs.record)
	return c
}
func (h *Host) getLogs(raw json.RawMessage) (any, *Error) {
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
	if p.Limit != nil && (string(p.Limit) == "null" || json.Unmarshal(p.Limit, &limit) != nil || limit < 1 || limit > 500) {
		return nil, fail("invalid_params", "params.limit", "Expected integer in 1..500")
	}
	if p.Instance != 0 && p.Instance != logInstance {
		after = 0
	}
	return h.logs.read(after, limit), nil
}
