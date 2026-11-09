package clientcore

import (
	"encoding/json"
	"fmt"
	"github.com/shui1iao/Kat/internal/kernel"
	"net"
	"net/netip"
	"strings"
	"sync"
)

type ConnectionEntry struct {
	Seq uint64 `json:"seq"`
	kernel.ConnectionEvent
}
type ConnectionLogsReply struct {
	Instance uint64            `json:"instance"`
	Entries  []ConnectionEntry `json:"entries"`
	NextSeq  uint64            `json:"next_seq"`
	Dropped  uint64            `json:"dropped"`
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
	if after > r.seq {
		after = 0
	}
	out := ConnectionLogsReply{Instance: logInstance, Entries: []ConnectionEntry{}, NextSeq: after, Dropped: r.dropped}
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
	return h.connectionLogs.read(after, limit), nil
}
func boundedLimit(raw json.RawMessage, limit *int, path string) *Error {
	if raw != nil && (string(raw) == "null" || json.Unmarshal(raw, limit) != nil || *limit < 1 || *limit > 500) {
		return fail("invalid_params", path, "Expected integer in 1..500")
	}
	return nil
}
func lanSubnetTarget(target string) string {
	if strings.Contains(target, "/16:") {
		return target
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || port == "" {
		return ""
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return ""
	}
	b := ip.As4()
	a0, a1 := b[0], b[1]
	if a0 == 10 || (a0 == 172 && a1 >= 16 && a1 <= 31) || (a0 == 192 && a1 == 168) || (a0 == 100 && a1 >= 64 && a1 <= 127) || (a0 == 169 && a1 == 254) {
		return fmt.Sprintf("%d.%d.0.0/16:%s", a0, a1, port)
	}
	return ""
}
func connGroupTarget(c kernel.ConnInfo) string {
	if c.DestHost == "" && c.Host == "" {
		if sub := lanSubnetTarget(c.Target); sub != "" {
			return sub
		}
	}
	if c.DestHost != "" {
		return c.DestHost + "|" + c.Target
	}
	if c.Host != "" {
		return c.Host + "|" + c.Target
	}
	return c.Target
}
func connBaseKey(c kernel.ConnInfo) string {
	t := connGroupTarget(c)
	if t == "" {
		return ""
	}
	return c.Network + "|" + t + "|" + c.Rule + "|" + strings.Join(c.Chain, "|")
}
func sameConnGroup(a, b kernel.ConnInfo) bool {
	ka, kb := connBaseKey(a), connBaseKey(b)
	if ka == "" || ka != kb {
		return false
	}
	return a.ProcessName == b.ProcessName || a.ProcessName == "" || b.ProcessName == ""
}
func mergeActiveConns(in []kernel.ConnInfo) []kernel.ConnInfo {
	if len(in) <= 1 {
		return in
	}
	out := make([]kernel.ConnInfo, 0, len(in))
	for _, c := range in {
		found := -1
		for i := range out {
			if sameConnGroup(out[i], c) {
				found = i
				break
			}
		}
		if found >= 0 {
			if out[found].Target != c.Target {
				if sub := lanSubnetTarget(c.Target); sub != "" {
					out[found].Target = sub
				}
			}
			out[found].Up += c.Up
			out[found].Down += c.Down
			if out[found].ProcessName == "" && c.ProcessName != "" {
				out[found].ProcessName = c.ProcessName
				out[found].ProcessPath = c.ProcessPath
				out[found].ProcessStatus = c.ProcessStatus
			}
			if c.DurationMS > out[found].DurationMS {
				out[found].DurationMS = c.DurationMS
				out[found].Start = c.Start
			}
			continue
		}
		out = append(out, c)
	}
	return out
}
func mergeClosedConns(in []kernel.ClosedConn) []kernel.ClosedConn {
	if len(in) <= 1 {
		return in
	}
	out := make([]kernel.ClosedConn, 0, len(in))
	for _, c := range in {
		found := -1
		for i := range out {
			if sameConnGroup(out[i].ConnInfo, c.ConnInfo) {
				found = i
				break
			}
		}
		if found >= 0 {
			if out[found].Target != c.Target {
				if sub := lanSubnetTarget(c.Target); sub != "" {
					out[found].Target = sub
				}
			}
			out[found].Up += c.Up
			out[found].Down += c.Down
			out[found].DurationMS += c.DurationMS
			if out[found].ProcessName == "" && c.ProcessName != "" {
				out[found].ProcessName = c.ProcessName
				out[found].ProcessPath = c.ProcessPath
				out[found].ProcessStatus = c.ProcessStatus
			}
			if c.End.After(out[found].End) {
				out[found].End = c.End
			}
			continue
		}
		out = append(out, c)
	}
	return out
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
		active = mergeActiveConns(active)
		closed = mergeClosedConns(closed)
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
		active, _ := h.server.ClientConnections(0)
		wanted := make(map[uint64]bool, len(p.IDs))
		var targets []kernel.ConnInfo
		for _, id := range p.IDs {
			wanted[id] = true
		}
		for _, c := range active {
			if wanted[c.ID] {
				targets = append(targets, c)
			}
		}
		ids := append([]uint64(nil), p.IDs...)
		for _, c := range active {
			if !wanted[c.ID] {
				for _, t := range targets {
					if sameConnGroup(t, c) {
						wanted[c.ID] = true
						ids = append(ids, c.ID)
						break
					}
				}
			}
		}
		n = h.server.ClientCloseConnections(ids)
	}
	return map[string]int{"closed": n}, nil
}
