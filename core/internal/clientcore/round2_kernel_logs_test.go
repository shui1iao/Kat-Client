package clientcore

import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/kernel"
	"strings"
	"testing"
	"time"
)

func TestRound2KernelLogsCapacityCursorAndParams(t *testing.T) {
	h := &Host{}
	for i := 0; i < 2010; i++ {
		h.kernelLogs.record(kernel.KernelLogEvent{Time: time.Now(), Level: "info", Message: "safe token=HIDDEN"})
	}
	h.kernelLogs.record(kernel.KernelLogEvent{Time: time.Now(), Level: "error", Message: "original failure"})
	r := h.kernelLogs.read(0, 500, "error")
	if len(r.Entries) != 1 || r.NextSeq != 2011 || r.Dropped != 11 {
		t.Fatal(r)
	}
	r = h.kernelLogs.read(0, 500, "")
	if len(r.Entries) != 500 || r.Entries[0].Seq != 12 || strings.Contains(r.Entries[0].Message, "HIDDEN") {
		t.Fatal(r)
	}
	for _, raw := range []string{`{"after":-1}`, `{"limit":501}`, `{"level":"bogus"}`, `{"extra":true}`} {
		if _, e := h.Request(context.Background(), "logs.kernel", json.RawMessage(raw)); e == nil {
			t.Fatal("accepted", raw)
		}
	}
	if _, e := h.Request(context.Background(), "logs.kernel", json.RawMessage(`{"after":0,"limit":500,"level":"info"}`)); e != nil {
		t.Fatal(e)
	}
}
