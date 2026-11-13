// Copyright 2026 The Kat Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package tcp

import (
	"runtime"
	stdsync "sync"
	"sync/atomic"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func resetWinSegmentPoolForTest() {
	winSegmentPool.mu.Lock()
	winSegmentPool.slots = nil
	winSegmentPool.mu.Unlock()
}

func TestWinBoundedSegmentPoolLifecycleAccountingAndQuota(t *testing.T) {
	want := runtime.GOOS == "windows"
	if useWinBoundedSegmentPool != want {
		t.Fatalf("useWinBoundedSegmentPool = %v, want %v on GOOS=%s", useWinBoundedSegmentPool, want, runtime.GOOS)
	}

	origFlag := useWinBoundedSegmentPool
	useWinBoundedSegmentPool = true
	defer func() {
		useWinBoundedSegmentPool = origFlag
		resetWinSegmentPoolForTest()
	}()
	resetWinSegmentPoolForTest()

	if winSegmentPool.slots != nil {
		t.Fatalf("winSegmentPool.slots should be nil before first release")
	}

	clock := tcpip.NewStdClock()
	ep := &Endpoint{}
	var pktReleased atomic.Int32

	s := newSegment()
	s.pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte("tcp-segment-payload")),
		OnRelease: func() {
			pktReleased.Add(1)
		},
	})
	s.dataMemSize = s.pkt.MemSize()
	s.options = make([]byte, 40)
	s.setOwner(ep, recvQ)

	expectedMem := s.segMemSize()
	if got := ep.receiveMemUsed(); got != expectedMem {
		t.Fatalf("ep.receiveMemUsed() = %d after setOwner, want %d", got, expectedMem)
	}

	var list segmentList
	list.PushBack(s)

	// IncRef to 2, then DecRef to 1: must NOT update receiveMemUsed, release pkt, or reset segment.
	s.IncRef()
	s.DecRef()
	if got := ep.receiveMemUsed(); got != expectedMem {
		t.Fatalf("ep.receiveMemUsed() changed prematurely on non-zero DecRef: got %d, want %d", got, expectedMem)
	}
	if pktReleased.Load() != 0 || s.ep == nil || s.pkt == nil || s.options == nil {
		t.Fatalf("segment reset or pkt released prematurely while refCount == 1")
	}
	if len(winSegmentPool.slots) != 0 {
		t.Fatalf("segment pooled prematurely while refCount == 1")
	}

	// Remove from list and final DecRef to 0: accounting updates first, pkt released, segment zeroed & pooled.
	list.Remove(s)
	s.DecRef()
	if got := ep.receiveMemUsed(); got != 0 {
		t.Fatalf("ep.receiveMemUsed() = %d after final DecRef, want 0", got)
	}
	if pktReleased.Load() != 1 {
		t.Fatalf("pktReleased = %d, want 1", pktReleased.Load())
	}
	if s.ep != nil || s.pkt != nil || s.options != nil || s.Next() != nil || s.Prev() != nil || s.qFlags != 0 || s.dataMemSize != 0 {
		t.Fatalf("segment fields not cleared before entering winSegmentPool: %+v", s)
	}
	if len(winSegmentPool.slots) != 1 || winSegmentPool.slots[0] != s {
		t.Fatalf("segment not pushed to winSegmentPool")
	}

	// Reuse segment: verify LIFO pop and slot nilled out.
	sReused := newSegment()
	if sReused != s {
		t.Fatalf("expected LIFO reuse of segment")
	}
	if winSegmentPool.slots[:cap(winSegmentPool.slots)][0] != nil {
		t.Fatalf("popped winSegmentPool slot was not cleared to nil")
	}
	sReused.pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{})
	sReused.DecRef()

	resetWinSegmentPoolForTest()

	// Quota test: allocate and release 2500 segments, pool caps at 2048, all 2500 have references cleared.
	const total = winSegmentPoolMaxSlots + 452
	segs := make([]*segment, total)
	for i := 0; i < total; i++ {
		seg := newOutgoingSegment(stack.TransportEndpointID{}, clock, buffer.MakeWithData([]byte("abc")), 0)
		seg.ep = ep
		seg.qFlags = sendQ
		seg.options = make([]byte, 12)
		segs[i] = seg
	}
	for i := 0; i < total; i++ {
		segs[i].DecRef()
	}
	if len(winSegmentPool.slots) != winSegmentPoolMaxSlots {
		t.Fatalf("len(winSegmentPool.slots) = %d, want %d", len(winSegmentPool.slots), winSegmentPoolMaxSlots)
	}
	for i, seg := range segs {
		if seg.ep != nil || seg.pkt != nil || seg.options != nil {
			t.Fatalf("segment %d references not cleared after DecRef", i)
		}
	}
}

func TestWinBoundedSegmentPoolConcurrentRace(t *testing.T) {
	origFlag := useWinBoundedSegmentPool
	useWinBoundedSegmentPool = true
	defer func() {
		useWinBoundedSegmentPool = origFlag
		resetWinSegmentPoolForTest()
	}()
	resetWinSegmentPoolForTest()

	clock := tcpip.NewStdClock()
	ep := &Endpoint{}
	var wg stdsync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				seg := newOutgoingSegment(stack.TransportEndpointID{}, clock, buffer.MakeWithData([]byte("payload")), 0)
				seg.ep = ep
				seg.qFlags = sendQ
				seg.options = []byte{1, 2, 3, 4}
				c := seg.clone()
				c.DecRef()
				seg.DecRef()
			}
		}()
	}
	wg.Wait()
}
