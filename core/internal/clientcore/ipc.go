package clientcore

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}
type Response struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Result any    `json:"result,omitempty"`
	Error  *Error `json:"error,omitempty"`
}

func decodeRequest(frame []byte) (Request, *Error) {
	var r Request
	if uniqueJSON(frame) != nil {
		return r, fail("invalid_request", "", "Invalid UTF-8 JSON frame")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(frame, &fields) != nil || fields == nil {
		return r, fail("invalid_request", "", "Request object required")
	}
	if b, ok := fields["id"]; !ok || json.Unmarshal(b, &r.ID) != nil {
		return r, fail("invalid_request", "id", "String id required")
	}
	if b, ok := fields["method"]; !ok || json.Unmarshal(b, &r.Method) != nil || r.Method == "" {
		return r, fail("invalid_request", "method", "Method string required")
	}
	for k := range fields {
		if k != "id" && k != "method" && k != "params" {
			return r, fail("invalid_request", "", "Unknown request field")
		}
	}
	r.Params = fields["params"]
	return r, nil
}

// TransportKind is selected by the native entry point, never by an IPC request.
// Its zero value retains the original stdio transport.
type TransportKind uint8

const (
	TransportStdio TransportKind = iota
	TransportNamedPipe
)

func (transport TransportKind) protocol() (string, error) {
	switch transport {
	case TransportStdio:
		return "stdio", nil
	case TransportNamedPipe:
		return "named_pipe", nil
	default:
		return "", errors.New("invalid IPC transport kind")
	}
}

// Serve preserves the original native stdio entry point.
func (h *Host) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	return h.ServeTransport(ctx, in, out, TransportStdio)
}

// ServeTransport owns request cancellation, not the Host lifetime. EOF cancels
// all child requests and joins bounded workers. The reader, including any bytes
// buffered during native activation, is consumed directly without replacement.
func (h *Host) ServeTransport(ctx context.Context, in io.Reader, out io.Writer, transport TransportKind) error {
	protocol, err := transport.protocol()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopInput := context.AfterFunc(ctx, func() {
		if c, ok := in.(io.Closer); ok {
			_ = c.Close()
		}
	})
	defer stopInput()
	var wg sync.WaitGroup
	// Scanner-owned admission barrier; these private methods are not WebView methods.
	updatePaused := false
	reqCtx, cancelReqs := context.WithCancel(ctx)
	defer cancelReqs()
	var writeMu sync.Mutex
	var writeErr error
	slots := make(chan struct{}, 16)
	logSlots := make(chan struct{}, 2)
	inflight := func() int { return len(slots) + len(logSlots) }
	ids := map[string]bool{}
	var idMu sync.Mutex
	report := func(stage, category string, id string, size int, inflight int) {
		d := outbound.Diagnostic{Stage: stage, Category: category, Protocol: protocol, Inflight: outbound.Known(uint64(inflight))}
		if n, e := strconv.ParseUint(strings.TrimPrefix(id, "h"), 10, 64); e == nil && strings.HasPrefix(id, "h") {
			d.RequestID = outbound.Known(n)
		}
		if size >= 0 {
			if stage == "ipc_read" || stage == "ipc_parse" || stage == "ipc_admission" {
				d.RequestBytes = outbound.Known(uint64(size))
			} else {
				d.ResponseBytes = outbound.Known(uint64(size))
			}
		}
		h.logs.record(kernel.ClientLogEvent{Time: time.Now(), Level: func() string {
			if category == "ok" {
				return "debug"
			}
			return "warn"
		}(), Event: "runtime.observation", Diagnostic: &d})
	}
	write := func(r Response, timing *ipcLogTiming) {
		var started time.Time
		if timing != nil {
			started = time.Now()
		}
		b, e := json.Marshal(r)
		if timing != nil {
			timing.encode = time.Since(started)
		}
		if e != nil || len(b) > MaxFrame {
			report("ipc_response", "frame_limit", r.ID, len(b), inflight())
			b, _ = json.Marshal(Response{ID: r.ID, OK: false, Error: fail("response_too_large", "", "Response exceeds frame limit")})
		}
		if timing != nil {
			started = time.Now()
		}
		writeMu.Lock()
		if timing != nil {
			timing.writeWait = time.Since(started)
		}
		defer func() {
			writeMu.Unlock()
			// Never add diagnostic work to the serialized output critical section.
			if timing != nil {
				h.recordSlowIPCLogs(r.ID, *timing, inflight(), transport)
			}
		}()
		if len(b) > MaxFrame {
			writeErr = errors.New("response cannot fit exact id within frame limit")
			cancel()
			return
		}
		if writeErr == nil {
			if timing != nil {
				started = time.Now()
			}
			_, writeErr = out.Write(append(b, '\n'))
			if timing != nil {
				timing.write = time.Since(started)
				timing.writeFailed = writeErr != nil
			}
			if writeErr != nil {
				h.recordTransportFailure("write", r.ID, len(b), inflight(), transport, writeErr)
			} else {
				report("ipc_response", "ok", r.ID, len(b), inflight())
			}
			if writeErr != nil {
				cancel()
			}
		}
	}
	type logReply struct {
		resp    Response
		timing  *ipcLogTiming
		release func()
	}
	logReplies := make(chan logReply, cap(logSlots))
	var logOutWG sync.WaitGroup
	logOutWG.Add(1)
	go func() {
		defer logOutWG.Done()
		for job := range logReplies {
			func(job logReply) {
				defer wg.Done()
				defer job.release()
				write(job.resp, job.timing)
			}(job)
		}
	}()
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64<<10), MaxFrame+2)
	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}
		frame := append([]byte(nil), scanner.Bytes()...)
		if len(frame) > MaxFrame {
			write(Response{Error: fail("frame_too_large", "", "Frame exceeds 2 MiB")}, nil)
			cancel()
			break
		}
		r, e := decodeRequest(frame)
		if e != nil {
			report("ipc_parse", "invalid_json", r.ID, len(frame), inflight())
			write(Response{ID: r.ID, Error: e}, nil)
			continue
		}
		var decoded time.Time
		if r.Method == "logs.get" {
			decoded = time.Now()
		}
		report("ipc_read", "ok", r.ID, len(frame), inflight())
		idMu.Lock()
		duplicate := ids[r.ID]
		if !duplicate {
			ids[r.ID] = true
		}
		idMu.Unlock()
		if duplicate {
			write(Response{ID: r.ID, Error: fail("duplicate_id", "id", "Request id already in flight")}, nil)
			continue
		}
		pool := slots
		if r.Method == "logs.get" {
			pool = logSlots
		}
		select {
		case pool <- struct{}{}:
		default:
			idMu.Lock()
			delete(ids, r.ID)
			idMu.Unlock()
			report("ipc_admission", "busy", r.ID, len(frame), inflight())
			write(Response{ID: r.ID, Error: fail("busy", "", "At most 16 requests may be in flight")}, nil)
			continue
		}
		release := func() { <-pool; idMu.Lock(); delete(ids, r.ID); idMu.Unlock() }
		if r.Method == "host.prepare-update" || r.Method == "host.resume-update" {
			// This runs on the scanner, not a worker: every earlier admitted
			// request (including workers not scheduled yet) finishes first.
			updatePaused = true
			if r.Method == "host.prepare-update" {
				cancelReqs()
			}
			wg.Wait()
			rctx, stop := context.WithTimeout(ctx, requestBudget(r.Method))
			result, err := h.Request(rctx, r.Method, r.Params)
			stop()
			if err != nil {
				if r.Method == "host.prepare-update" {
					reqCtx, cancelReqs = context.WithCancel(ctx)
				}
				write(Response{ID: r.ID, Error: err}, nil)
			} else {
				write(Response{ID: r.ID, OK: true, Result: result}, nil)
				if r.Method == "host.resume-update" {
					reqCtx, cancelReqs = context.WithCancel(ctx)
					updatePaused = false
				}
			}
			release()
			continue
		}
		if updatePaused {
			write(Response{ID: r.ID, Error: fail("update_prepared", "", "Core requests are paused for update")}, nil)
			release()
			continue
		}
		if r.Method == "logs.get" {
			started := time.Now()
			timing := &ipcLogTiming{admission: started.Sub(decoded)}
			rctx, stop := context.WithTimeout(reqCtx, requestBudget(r.Method))
			result, err := h.Request(rctx, r.Method, r.Params)
			stop()
			timing.handler = time.Since(started)
			resp := Response{ID: r.ID, OK: err == nil, Result: result, Error: err}
			wg.Add(1)
			logReplies <- logReply{resp: resp, timing: timing, release: release}
			continue
		}
		parentCtx := ctx
		if isBackgroundIPCMethod(r.Method) {
			parentCtx = reqCtx
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-pool }()
			rctx, stop := context.WithTimeout(parentCtx, requestBudget(r.Method))
			defer stop()
			result, err := h.Request(rctx, r.Method, r.Params)
			idMu.Lock()
			delete(ids, r.ID)
			idMu.Unlock()
			if err != nil {
				write(Response{ID: r.ID, Error: err}, nil)
			} else {
				write(Response{ID: r.ID, OK: true, Result: result}, nil)
			}
		}()
	}
	close(logReplies)
	logOutWG.Wait()
	scanErr := scanner.Err()
	if scanErr != nil {
		h.recordTransportFailure("read", "", -1, inflight(), transport, scanErr)
		failure := fail("frame_too_large", "", "Frame exceeds limit or input failed")
		failure.Transport = scannerDiagnostic(scanErr)
		write(Response{Error: failure}, nil)
	}
	cancel()
	wg.Wait()
	if writeErr != nil {
		return errors.New("IPC output unavailable")
	}
	return scanErr
}

func isBackgroundIPCMethod(method string) bool {
	switch method {
	case "icon.get", "icon.cached", "probe.node", "probe.group", "probe.all", "diagnostics.network", "dns.query", "resources.refresh", "subscription.preview", "subscription.migrate", "import.parse", "connections.list", "status", "logs.get", "logs.connections", "logs.kernel":
		return true
	default:
		return false
	}
}

// Only these methods admit configured work beyond the ordinary frame budget.
func requestBudget(method string) time.Duration {
	switch method {
	case "network.tun.disable":
		return 45 * time.Second
	case "network.tun.prepare", "network.tun.commit":
		return 65 * time.Second
	case "diagnostics.network":
		return 70 * time.Second
	case "subscription.preview", "subscription.migrate":
		return 185 * time.Second
	case "probe.node", "probe.group", "probe.all", "resources.refresh", "dns.query":
		return 305 * time.Second
	default:
		return 35 * time.Second
	}
}
