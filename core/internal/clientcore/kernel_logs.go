package clientcore

import (
	"encoding/json"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/logsafe"
	"sync"
)

type KernelLogEntry struct {
	Seq uint64 `json:"seq"`
	kernel.KernelLogEvent
}
type KernelLogsReply struct {
	Instance uint64           `json:"instance"`
	Entries  []KernelLogEntry `json:"entries"`
	NextSeq  uint64           `json:"next_seq"`
	Dropped  uint64           `json:"dropped"`
}
type kernelLogRing struct {
	mu           sync.Mutex
	entries      [logCapacity]KernelLogEntry
	seq, dropped uint64
	size         int
}

func (r *kernelLogRing) record(e kernel.KernelLogEvent) {
	if !validKernelLevel(e.Level) {
		return
	}
	e.Message = logsafe.Text(e.Message)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seq == maxLogSeq {
		return
	}
	r.seq++
	r.entries[(r.seq-1)%logCapacity] = KernelLogEntry{r.seq, e}
	if r.size < logCapacity {
		r.size++
	} else {
		r.dropped++
	}
}
func validKernelLevel(s string) bool {
	return s == "debug" || s == "info" || s == "warn" || s == "error"
}
func kernelRank(s string) int {
	switch s {
	case "debug":
		return 0
	case "warn":
		return 2
	case "error":
		return 3
	}
	return 1
}
func (r *kernelLogRing) read(after uint64, limit int, level string) KernelLogsReply {
	r.mu.Lock()
	defer r.mu.Unlock()
	if after > r.seq {
		after = 0
	}
	out := KernelLogsReply{Instance: logInstance, Entries: []KernelLogEntry{}, NextSeq: after, Dropped: r.dropped}
	if after >= r.seq {
		return out
	}
	first := r.seq - uint64(r.size) + 1
	if after >= first {
		first = after + 1
	}
	for seq := first; seq <= r.seq; seq++ {
		out.NextSeq = seq
		e := r.entries[(seq-1)%logCapacity]
		if level == "" || kernelRank(e.Level) >= kernelRank(level) {
			out.Entries = append(out.Entries, e)
			if len(out.Entries) == limit {
				break
			}
		}
	}
	return out
}
func (h *Host) getKernelLogs(raw json.RawMessage) (any, *Error) {
	var p struct {
		Instance uint64          `json:"instance,omitempty"`
		After    json.RawMessage `json:"after"`
		Limit    json.RawMessage `json:"limit"`
		Level    string          `json:"level"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	var after uint64
	limit := 500
	if p.After != nil && (string(p.After) == "null" || json.Unmarshal(p.After, &after) != nil || after > maxLogSeq) {
		return nil, fail("invalid_params", "params.after", "Expected nonnegative safe integer")
	}
	if e := boundedLimit(p.Limit, &limit, "params.limit"); e != nil {
		return nil, e
	}
	if p.Level != "" && !validKernelLevel(p.Level) {
		return nil, fail("invalid_params", "params.level", "Expected debug/info/warn/error")
	}
	if p.Instance != 0 && p.Instance != logInstance {
		after = 0
	}
	return h.kernelLogs.read(after, limit, p.Level), nil
}
