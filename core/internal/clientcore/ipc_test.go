package clientcore

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestIPCBoundedInflightProbeConcurrencyAndEOF(t *testing.T) {
	var active, peak atomic.Int32
	started := make(chan struct{}, 32)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer target.Close()
	h := newHost(t)
	text := settingsText(t, fixture(t, map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}}), map[string]any{"probe_concurrency": 4})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	defer outR.Close()
	defer inW.Close()
	done := make(chan error, 1)
	go func() { e := h.Serve(context.Background(), inR, outW); outW.Close(); done <- e }()
	responses := make(chan map[string]json.RawMessage, 32)
	go func() {
		s := bufio.NewScanner(outR)
		s.Buffer(make([]byte, 64<<10), MaxFrame+2)
		for s.Scan() {
			var r map[string]json.RawMessage
			if json.Unmarshal(s.Bytes(), &r) == nil {
				responses <- r
			}
		}
		close(responses)
	}()
	for i := 0; i < 16; i++ {
		b, _ := json.Marshal(map[string]any{"id": fmt.Sprint(i), "method": "probe.node", "params": map[string]any{"name": "direct", "url": target.URL}})
		if _, e := inW.Write(append(b, '\n')); e != nil {
			t.Fatal(e)
		}
	}
	for range 4 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("4 probes not started")
		}
	}
	if peak.Load() != 4 {
		t.Fatal("probe concurrency not bounded at four")
	}
	fmt.Fprintln(inW, `{"id":"overflow","method":"hello"}`)
	select {
	case r := <-responses:
		if string(r["id"]) != `"overflow"` || string(r["ok"]) != "false" {
			t.Fatal("inflight limit not enforced")
		}
	case <-time.After(time.Second):
		t.Fatal("overflow blocked input")
	}
	inW.Close()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("EOF leaked inflight workers")
	}
	count := 0
	for range responses {
		count++
	}
	if count != 16 {
		t.Fatal("EOF response correlation lost")
	}
	if peak.Load() > 4 {
		t.Fatal("manual probes exceeded 4")
	}
}
func TestExactFrameAndInvalidUTF8(t *testing.T) {
	h := newHost(t)
	input, output := io.Pipe()
	reader, writer := io.Pipe()
	defer reader.Close()
	done := make(chan error, 1)
	go func() { done <- h.Serve(context.Background(), input, writer); writer.Close() }()
	go func() {
		prefix := `{"id":"edge","method":"hello","padding":"`
		suffix := `"}`
		frame := make([]byte, MaxFrame)
		copy(frame, prefix)
		for i := len(prefix); i < len(frame)-len(suffix); i++ {
			frame[i] = 'x'
		}
		copy(frame[len(frame)-len(suffix):], suffix)
		output.Write(append(frame, '\n'))
		output.Write([]byte{'{', 0xff, '}', '\n'})
		output.Close()
	}()
	s := bufio.NewScanner(reader)
	s.Buffer(make([]byte, 64<<10), MaxFrame+2)
	n := 0
	for s.Scan() {
		var r Response
		if json.Unmarshal(s.Bytes(), &r) != nil || r.OK || r.Error == nil {
			t.Fatal("invalid input accepted")
		}
		if n == 0 && r.Error.Code == "frame_too_large" {
			t.Fatal("exact frame rejected as oversized")
		}
		n++
	}
	if n != 2 {
		t.Fatal("frame synchronization")
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
