package clientcore

import (
	"encoding/json"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/shui1iao/Kat/internal/kernel"
)

const logCapacity = 2000
const maxLogSeq = 9007199254740991 // exact JavaScript integer

type LogEntry struct {
	Seq   uint64 `json:"seq"`
	Time  string `json:"time"`
	Level string `json:"level"`
	Event string `json:"event"`
	Code  string `json:"code,omitempty"`
	Group string `json:"group,omitempty"`
}
type LogsReply struct {
	Entries []LogEntry `json:"entries"`
	NextSeq uint64     `json:"next_seq"`
	Dropped uint64     `json:"dropped"`
}

// One ring per Host/process, not per kernel generation. Stop/start does not
// insert entries or reset the cursor; a new process starts empty.
type logRing struct {
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
	if len(e.Event) == 0 || len(e.Event) > 64 || len(e.Code) > 64 {
		return
	}
	switch e.Level {
	case "debug", "info", "warn", "error":
	default:
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seq == maxLogSeq {
		return
	}
	r.seq++
	r.entries[(r.seq-1)%logCapacity] = LogEntry{Seq: r.seq, Time: e.Time.UTC().Format(time.RFC3339Nano), Level: e.Level, Event: e.Event, Code: e.Code, Group: name}
	if r.size < logCapacity {
		r.size++
	} else {
		r.dropped++
	}
}
func (r *logRing) read(after uint64, limit int) LogsReply {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := LogsReply{Entries: []LogEntry{}, NextSeq: after, Dropped: r.dropped}
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
		After json.RawMessage `json:"after"`
		Limit json.RawMessage `json:"limit"`
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
	return h.logs.read(after, limit), nil
}
