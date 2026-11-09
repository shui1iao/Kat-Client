package clientcore

import (
	"strconv"
	"strings"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound"
)

// Only logs.get uses this retrospective timing. No background sampler, payload,
// new protocol field, cancellation, or extra response buffer is introduced.
const ipcLogSlowPhase = 250 * time.Millisecond

type ipcLogTiming struct {
	admission, handler, encode, writeWait, write time.Duration
	writeFailed                                  bool
}

func (p ipcLogTiming) slowest() (string, time.Duration) {
	stage, elapsed := "ipc_admission", p.admission // decoded frame -> worker's handler call
	for _, phase := range [...]struct {
		stage   string
		elapsed time.Duration
	}{
		{"ipc_request", p.handler}, // includes the log ring mutex, not Host.mu
		{"ipc_parse", p.encode},    // JSON response encoding, not request decoding
		{"ipc_write", p.writeWait}, // waiting for serialized output ownership
		{"ipc_response", p.write},  // the actual output Write call
	} {
		if phase.elapsed > elapsed {
			stage, elapsed = phase.stage, phase.elapsed
		}
	}
	return stage, elapsed
}

func (h *Host) recordSlowIPCLogs(id string, timing ipcLogTiming, inflight int, transport TransportKind) {
	protocol, err := transport.protocol()
	if err != nil {
		return
	}
	stage, elapsed := timing.slowest()
	if elapsed < ipcLogSlowPhase {
		return
	}
	d := outbound.Diagnostic{Stage: stage, Category: "ok", Protocol: protocol, Action: "request_end", ElapsedMS: outbound.Known(uint64(elapsed.Milliseconds())), Inflight: outbound.Known(uint64(inflight))}
	// "ok" means this measured phase returned, not that the application reply
	// was successful. Keep a real output write failure a failure observation.
	if stage == "ipc_response" && timing.writeFailed {
		d.Category = "write_failed"
	}
	if n, e := strconv.ParseUint(strings.TrimPrefix(id, "h"), 10, 64); e == nil && strings.HasPrefix(id, "h") {
		d.RequestID = outbound.Known(n)
	}
	level := "debug"
	if d.Category != "ok" {
		level = "warn"
	}
	// At most one phase per slow request, through the existing bounded ring and
	// per-key gate (30s for ok). request_end distinguishes it from routine I/O.
	h.logs.record(kernel.ClientLogEvent{Time: time.Now(), Level: level, Event: "runtime.observation", Diagnostic: &d})
}
