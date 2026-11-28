package kernel

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/stats"
)

func TestCopyAdaptiveDemotesAndPromotes(t *testing.T) {
	chunks := [][]byte{
		bytes.Repeat([]byte("a"), 512),   // small read -> demotes 64KiB -> 8KiB
		bytes.Repeat([]byte("b"), 256),   // stays 8KiB
		bytes.Repeat([]byte("c"), 16384), // fills 8KiB -> promotes back to 64KiB
		bytes.Repeat([]byte("d"), 65535), // delivered in 1 large write
	}
	var want bytes.Buffer
	for _, c := range chunks {
		want.Write(c)
	}
	src := &recordChunkConn{readChunks: chunks}
	dst := &recordChunkConn{}
	s := &Server{
		core: &core{reg: stats.New(nil, nil, nil, nil, time.Now())},
		pool: newBufferPool(64<<10, 8),
	}
	f, ctx := s.newFlow(context.Background(), "tcp", Address{})
	_, down := meters(ctx)
	if err := s.copyM(dst, src, down); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst.written.Bytes(), want.Bytes()) {
		t.Fatal("adaptive copy payload mismatch")
	}
	if f.down.Load() != uint64(want.Len()) {
		t.Fatalf("meter mismatch: got %d, want %d", f.down.Load(), want.Len())
	}
	if drained := s.pool.drain(); drained == 0 {
		t.Fatal("expected idle pooled buffer to be drained")
	}
	if drained := s.pool.drain(); drained != 0 {
		t.Fatalf("expected second drain to drop 0, got %d", drained)
	}
}
