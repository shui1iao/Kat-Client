package clientcore

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
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

// Serve owns request cancellation, not the Host lifetime. EOF cancels all child
// requests, joins bounded workers, then the caller closes the actual core.
func (h *Host) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopInput := context.AfterFunc(ctx, func() {
		if c, ok := in.(io.Closer); ok {
			_ = c.Close()
		}
	})
	defer stopInput()
	var wg sync.WaitGroup
	var writeMu sync.Mutex
	var writeErr error
	slots := make(chan struct{}, 16)
	ids := map[string]bool{}
	var idMu sync.Mutex
	write := func(r Response) {
		b, e := json.Marshal(r)
		if e != nil || len(b) > MaxFrame {
			b, _ = json.Marshal(Response{ID: r.ID, OK: false, Error: fail("response_too_large", "", "Response exceeds frame limit")})
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		if len(b) > MaxFrame {
			writeErr = errors.New("response cannot fit exact id within frame limit")
			cancel()
			return
		}
		if writeErr == nil {
			_, writeErr = out.Write(append(b, '\n'))
			if writeErr != nil {
				cancel()
			}
		}
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64<<10), MaxFrame+2)
	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}
		frame := append([]byte(nil), scanner.Bytes()...)
		if len(frame) > MaxFrame {
			write(Response{Error: fail("frame_too_large", "", "Frame exceeds 2 MiB")})
			cancel()
			break
		}
		r, e := decodeRequest(frame)
		if e != nil {
			write(Response{ID: r.ID, Error: e})
			continue
		}
		idMu.Lock()
		duplicate := ids[r.ID]
		if !duplicate {
			ids[r.ID] = true
		}
		idMu.Unlock()
		if duplicate {
			write(Response{ID: r.ID, Error: fail("duplicate_id", "id", "Request id already in flight")})
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			idMu.Lock()
			delete(ids, r.ID)
			idMu.Unlock()
			write(Response{ID: r.ID, Error: fail("busy", "", "At most 16 requests may be in flight")})
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots; idMu.Lock(); delete(ids, r.ID); idMu.Unlock() }()
			rctx, stop := context.WithTimeout(ctx, requestBudget(r.Method))
			defer stop()
			result, err := h.Request(rctx, r.Method, r.Params)
			if err != nil {
				write(Response{ID: r.ID, Error: err})
			} else {
				write(Response{ID: r.ID, OK: true, Result: result})
			}
		}()
	}
	scanErr := scanner.Err()
	if scanErr != nil {
		write(Response{Error: fail("frame_too_large", "", "Frame exceeds limit or input failed")})
	}
	cancel()
	wg.Wait()
	if writeErr != nil {
		return errors.New("IPC output unavailable")
	}
	return scanErr
}

// Only these methods admit configured work beyond the ordinary frame budget.
func requestBudget(method string) time.Duration {
	switch method {
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
