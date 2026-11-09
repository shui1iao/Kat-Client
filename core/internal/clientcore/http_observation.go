package clientcore

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/procattr"
	"net"
	"sync/atomic"
	"time"
)

var nextHTTPObservationID atomic.Uint64

type httpTraceKey struct{}

// bridgeID identifies an accepted local HTTP connection; requestID one request.
// Sequence is observation order only, NOT wire order or proof of root cause.
// No locks, waits, workers, socket addresses, targets or error text enter this trace.
type httpTrace struct {
	bridgeID, requestID    uint64
	start                  time.Time
	connect                bool
	seq, flowID, lastClose atomic.Uint64
	sink                   func(kernel.ClientLogEvent)
}

func (b *httpBridge) newTrace(ctx context.Context, connect bool) *httpTrace {
	if b.log == nil {
		return nil
	}
	id := nextHTTPObservationID.Add(1)
	t := &httpTrace{bridgeID: id, requestID: id, start: time.Now(), sink: b.log, connect: connect}
	if v, _ := ctx.Value(httpOriginKey{}).(*httpOrigin); v != nil {
		t.bridgeID = v.bridgeID
	}
	return t
}
func httpTraceOf(ctx context.Context) *httpTrace {
	t, _ := ctx.Value(httpTraceKey{}).(*httpTrace)
	return t
}
func (t *httpTrace) decorate(d *outbound.Diagnostic) {
	if t == nil {
		return
	}
	d.BridgeID, d.RequestID = outbound.Known(t.bridgeID), outbound.Known(t.requestID)
	// Capture only a close already observed before this sequence marker.
	n := t.lastClose.Load()
	d.ObservationSeq = outbound.Known(t.seq.Add(1))
	if n != 0 {
		d.ObservedCloseSeq = outbound.Known(n)
	}
}
func (t *httpTrace) registration() *procattr.HTTPObservation {
	if t == nil || !t.connect {
		return nil
	} // HTTP pooling cannot prove one request-to-flow binding.
	return &procattr.HTTPObservation{Bind: func(id uint64) { t.flowID.Store(id); t.record("bind", "none", "", nil, 0) }, Decorate: func(d *outbound.Diagnostic) { t.decorate(d); d.Action = "flow_observation" }}
}
func (t *httpTrace) record(action, direction, trigger string, err error, related uint64) uint64 {
	if t == nil {
		return 0
	}
	category, native := outbound.Category(err)
	d := outbound.Diagnostic{Stage: "http_bridge", Protocol: "http", Category: category, Native: native, Action: action, Direction: direction, Trigger: trigger, ElapsedMS: outbound.Known(uint64(time.Since(t.start).Milliseconds()))}
	t.decorate(&d)
	n := *d.ObservationSeq
	if related != 0 {
		d.RelatedSeq = outbound.Known(related)
	}
	if action == "close_begin" || action == "half_close_begin" {
		for old := t.lastClose.Load(); n > old && !t.lastClose.CompareAndSwap(old, n); old = t.lastClose.Load() {
		}
	}
	if id := t.flowID.Load(); id != 0 {
		d.FlowID = outbound.Known(id)
	} else {
		unavailable := true
		d.SnapshotUnavailable = &unavailable
	}
	var op *net.OpError
	if errors.As(err, &op) {
		switch op.Op {
		case "read", "write", "close":
			d.IOOperation = op.Op
		default:
			d.IOOperation = "unknown"
		}
	}
	if !d.Valid() {
		return n
	}
	level := "debug"
	if err != nil && !((action == "close_end" || action == "half_close_end") && errors.Is(err, net.ErrClosed)) && category != "canceled" && category != "closed" && action != "copy_end" && !(category == "os_error" && native != nil && (*native == 10053 || *native == 10054)) {
		level = "warn"
	}
	t.sink(kernel.ClientLogEvent{Time: time.Now(), Level: level, Event: "runtime.observation", Diagnostic: &d})
	return n
}

// Exactly one original operation, at the original call site. related identifies
// an explicit local trigger/own-close call, never an inferred network cause.
func (t *httpTrace) close(leg, trigger string, related uint64, close func() error) {
	n := t.record("close_begin", leg, trigger, nil, related)
	err := close()
	t.record("close_end", leg, trigger, err, n)
}
func (t *httpTrace) halfClose(leg, trigger string, related uint64, close func() error) {
	n := t.record("half_close_begin", leg, trigger, nil, related)
	err := close()
	t.record("half_close_end", leg, trigger, err, n)
}
