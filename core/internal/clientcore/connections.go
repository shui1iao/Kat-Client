package clientcore

import (
	"encoding/json"
	"github.com/shui1iao/Kat/internal/kernel"
	"sync"
)

type ConnectionEntry struct {
	Seq uint64 `json:"seq"`
	kernel.ConnectionEvent
}
type ConnectionLogsReply struct {
	Entries []ConnectionEntry `json:"entries"`
	NextSeq uint64            `json:"next_seq"`
	Dropped uint64            `json:"dropped"`
}
type connectionRing struct {
	mu           sync.Mutex
	entries      [logCapacity]ConnectionEntry
	seq, dropped uint64
	size         int
}

func (r *connectionRing) record(e kernel.ConnectionEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seq == maxLogSeq {
		return
	}
	r.seq++
	e.DestIPs = append([]string(nil), e.DestIPs...)
	e.Chain = append([]string{}, e.Chain...)
	r.entries[(r.seq-1)%logCapacity] = ConnectionEntry{r.seq, e}
	if r.size < logCapacity {
		r.size++
	} else {
		r.dropped++
	}
}
func (r *connectionRing) read(after uint64, limit int) ConnectionLogsReply {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := ConnectionLogsReply{Entries: []ConnectionEntry{}, NextSeq: after, Dropped: r.dropped}
	if after >= r.seq {
		return out
	}
	first := r.seq - uint64(r.size) + 1
	if after >= first {
		first = after + 1
	}
	for seq := first; seq <= r.seq && len(out.Entries) < limit; seq++ {
		e := r.entries[(seq-1)%logCapacity]
		e.DestIPs = append([]string(nil), e.DestIPs...)
		e.Chain = append([]string{}, e.Chain...)
		out.Entries = append(out.Entries, e)
		out.NextSeq = seq
	}
	return out
}
func (h *Host) getConnectionLogs(raw json.RawMessage) (any, *Error) {
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
	if e := boundedLimit(p.Limit, &limit, "params.limit"); e != nil {
		return nil, e
	}
	return h.connectionLogs.read(after, limit), nil
}
func boundedLimit(raw json.RawMessage, limit *int, path string) *Error {
	if raw != nil && (string(raw) == "null" || json.Unmarshal(raw, limit) != nil || *limit < 1 || *limit > 500) {
		return fail("invalid_params", path, "Expected integer in 1..500")
	}
	return nil
}
func (h *Host) listConnections(raw json.RawMessage) (any, *Error) {
	var p struct {
		Limit json.RawMessage `json:"closed_limit"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	limit := 200
	if e := boundedLimit(p.Limit, &limit, "params.closed_limit"); e != nil {
		return nil, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	active, closed := []kernel.ConnInfo{}, []kernel.ClosedConn{}
	var total any
	if h.server != nil {
		active, closed = h.server.ClientConnections(limit)
		total = h.server.TotalConnections()
	}
	return map[string]any{"active": active, "closed": closed, "total": total}, nil
}

func (h *Host) closeConnections(raw json.RawMessage) (any, *Error) {
	var p struct {
		IDs []uint64 `json:"ids"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	if p.IDs == nil || len(p.IDs) > MaxFrame/2 {
		return nil, fail("invalid_params", "params.ids", "Connection id list exceeds frame budget")
	}
	for _, id := range p.IDs {
		if id == 0 || id > maxLogSeq {
			return nil, fail("invalid_params", "params.ids", "Expected positive safe ids")
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	if h.server != nil {
		n = h.server.ClientCloseConnections(p.IDs)
	}
	return map[string]int{"closed": n}, nil
}
