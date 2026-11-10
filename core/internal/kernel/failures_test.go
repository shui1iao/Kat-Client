package kernel

import (
	"bytes"

	"errors"

	"strings"
	"sync"
	"testing"
	"time"
)

func TestFailureCategoriesBoundedAndPrivate(t *testing.T) {
	var b bytes.Buffer
	l := &failureLog{write: func(p []byte) error { _, e := b.Write(p); return e }}
	now := time.Unix(200, 0)
	for k := failureKind(0); k < failureKinds; k++ {
		l.emit(k, "password=evil.example 203.0.113.42 payload", 999, now)
		for i := 0; i < 100; i++ {
			l.emit(k, "anytls", 0, now.Add(time.Second))
		}
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != int(failureKinds) {
		t.Fatal("rate cap", len(lines))
	}
	for _, line := range lines {
		if len(line) > 220 || !strings.Contains(line, "protocol=other inbound=-1 suppressed=0") {
			t.Fatal("unsafe shape", line)
		}
	}
	for _, secret := range []string{"password", "evil.example", "203.0.113.42", "payload"} {
		if strings.Contains(b.String(), secret) {
			t.Fatal("input leaked")
		}
	}
	b.Reset()
	l.emit(failTLS, "anytls", 3, now.Add(5*time.Second))
	if !strings.Contains(b.String(), "suppressed=100") {
		t.Fatal("missing suppressed count", b.String())
	}
}

func TestFailureConcurrentCapAndBrokenSink(t *testing.T) {
	var mu sync.Mutex
	n := 0
	l := &failureLog{write: func(p []byte) error { mu.Lock(); n++; mu.Unlock(); return errors.New("sink unavailable") }}
	now := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.emit(failUDPInvalid, "shadowsocks", 0, now)
			}
		}()
	}
	wg.Wait()
	if n != 1 || l.buckets[failUDPInvalid].suppressed.Load() != 3200 {
		t.Fatal("unbounded or lost suppression", n, l.buckets[failUDPInvalid].suppressed.Load())
	}
}
