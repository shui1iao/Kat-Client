// Copyright 2026 The Kat Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package stack

import (
	"runtime"
	stdsync "sync"
	"sync/atomic"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type dummyPacketOwner struct{}

func (*dummyPacketOwner) KUID() uint32 { return 1000 }
func (*dummyPacketOwner) KGID() uint32 { return 1000 }

func resetWinPkPoolForTest() {
	winPkPool.mu.Lock()
	winPkPool.slots = nil
	winPkPool.mu.Unlock()
}

func TestWinBoundedPkPoolLifecycleCallbackAndQuota(t *testing.T) {
	want := runtime.GOOS == "windows"
	if useWinBoundedPkPool != want {
		t.Fatalf("useWinBoundedPkPool = %v, want %v on GOOS=%s", useWinBoundedPkPool, want, runtime.GOOS)
	}

	origFlag := useWinBoundedPkPool
	useWinBoundedPkPool = true
	defer func() {
		useWinBoundedPkPool = origFlag
		resetWinPkPoolForTest()
	}()
	resetWinPkPoolForTest()

	if winPkPool.slots != nil {
		t.Fatalf("winPkPool.slots should be nil before first release")
	}

	var releaseCount atomic.Int32
	var fieldsIntactDuringCallback atomic.Bool
	var pk *PacketBuffer
	pk = NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: 64,
		Payload:            buffer.MakeWithData([]byte("packet-payload")),
		Mark:               0xCAFE,
		OnRelease: func() {
			releaseCount.Add(1)
			// Verify pk has NOT been reset while OnRelease is executing.
			if pk.Mark == 0xCAFE && pk.Owner != nil && pk.tuple != nil && pk.buf.Size() > 0 {
				fieldsIntactDuringCallback.Store(true)
			}
		},
	})
	pk.Owner = &dummyPacketOwner{}
	pk.tuple = &tuple{}
	pk.Hash = 12345
	pk.NICID = 3
	pk.EgressRoute.NetProto = tcpip.NetworkProtocolNumber(0x0800)

	// Still nil before any DecRef reaches 0.
	if winPkPool.slots != nil {
		t.Fatalf("winPkPool.slots should remain nil before first Put")
	}

	// IncRef to 2, then DecRef to 1: must NOT invoke OnRelease, must NOT reset or pool.
	pk.IncRef()
	pk.DecRef()
	if releaseCount.Load() != 0 {
		t.Fatalf("OnRelease called when refCount > 0")
	}
	if pk.Mark != 0xCAFE || pk.Owner == nil || pk.tuple == nil {
		t.Fatalf("PacketBuffer reset prematurely while refCount == 1")
	}
	if len(winPkPool.slots) != 0 {
		t.Fatalf("PacketBuffer pooled prematurely while refCount == 1")
	}

	// Test Clone and CloneToInbound while pk is active.
	cloned := pk.Clone()
	inbound := pk.CloneToInbound()
	cloned.DecRef()
	inbound.DecRef()
	if len(winPkPool.slots) != 2 {
		t.Fatalf("expected cloned and inbound PacketBuffers in pool, got %d", len(winPkPool.slots))
	}

	// Final DecRef on pk reaches refCount == 0: OnRelease runs once, buf released, fields reset, pk pooled.
	pk.DecRef()
	if releaseCount.Load() != 1 {
		t.Fatalf("OnRelease count = %d, want 1", releaseCount.Load())
	}
	if !fieldsIntactDuringCallback.Load() {
		t.Fatalf("PacketBuffer fields were reset before OnRelease finished executing")
	}
	if pk.onRelease != nil || pk.Owner != nil || pk.tuple != nil || pk.Mark != 0 || pk.Hash != 0 || pk.NICID != 0 || pk.buf.Size() != 0 {
		t.Fatalf("PacketBuffer fields were not cleared before entering winPkPool: %+v", pk)
	}
	if len(winPkPool.slots) != 3 || winPkPool.slots[2] != pk {
		t.Fatalf("pk was not pushed to top of winPkPool")
	}

	// Reuse pk from pool: slot must be nilled, and subsequent DecRef must NOT re-trigger old OnRelease.
	reused := NewPacketBuffer(PacketBufferOptions{})
	if reused != pk {
		t.Fatalf("expected LIFO reuse of pk")
	}
	if winPkPool.slots[:cap(winPkPool.slots)][2] != nil {
		t.Fatalf("popped winPkPool slot was not cleared to nil")
	}
	reused.DecRef()
	if releaseCount.Load() != 1 {
		t.Fatalf("old OnRelease was called again on reused PacketBuffer: count=%d", releaseCount.Load())
	}

	resetWinPkPoolForTest()

	// Quota test: release 2500 PacketBuffers, pool caps at 2048, all 2500 are reset.
	const total = winPkPoolMaxSlots + 452
	var batchReleaseCount atomic.Int32
	pks := make([]*PacketBuffer, total)
	for i := 0; i < total; i++ {
		p := NewPacketBuffer(PacketBufferOptions{
			ReserveHeaderBytes: 64,
			OnRelease: func() {
				batchReleaseCount.Add(1)
			},
		})
		p.Owner = &dummyPacketOwner{}
		p.tuple = &tuple{}
		pks[i] = p
	}
	for i := 0; i < total; i++ {
		pks[i].DecRef()
	}
	if int(batchReleaseCount.Load()) != total {
		t.Fatalf("batchReleaseCount = %d, want %d", batchReleaseCount.Load(), total)
	}
	if len(winPkPool.slots) != winPkPoolMaxSlots {
		t.Fatalf("len(winPkPool.slots) = %d, want %d", len(winPkPool.slots), winPkPoolMaxSlots)
	}
	for i, p := range pks {
		if p.onRelease != nil || p.Owner != nil || p.tuple != nil || p.buf.Size() != 0 {
			t.Fatalf("PacketBuffer %d not cleared after DecRef", i)
		}
	}
}

func TestWinBoundedPkPoolConcurrentRace(t *testing.T) {
	origFlag := useWinBoundedPkPool
	useWinBoundedPkPool = true
	defer func() {
		useWinBoundedPkPool = origFlag
		resetWinPkPoolForTest()
	}()
	resetWinPkPoolForTest()

	var wg stdsync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				pk := NewPacketBuffer(PacketBufferOptions{
					ReserveHeaderBytes: 64,
					Payload:            buffer.MakeWithData([]byte("race-payload")),
				})
				pk.Owner = &dummyPacketOwner{}
				c1 := pk.Clone()
				c2 := pk.CloneToInbound()
				c1.DecRef()
				c2.DecRef()
				pk.DecRef()
			}
		}()
	}
	wg.Wait()
}
