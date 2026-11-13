// Copyright 2026 The Kat Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package buffer

import (
	"bytes"
	"runtime"
	stdsync "sync"
	"testing"
)

func resetWinBufferPoolsForTest() {
	for i := range winChunkPools {
		winChunkPools[i].mu.Lock()
		winChunkPools[i].slots = nil
		winChunkPools[i].mu.Unlock()
	}
	winViewPool.mu.Lock()
	winViewPool.slots = nil
	winViewPool.mu.Unlock()
}

func TestWinBoundedBufferPoolsDefaultPlatformGuard(t *testing.T) {
	want := runtime.GOOS == "windows"
	if useWinBoundedChunkPool != want {
		t.Fatalf("useWinBoundedChunkPool = %v, want %v on GOOS=%s", useWinBoundedChunkPool, want, runtime.GOOS)
	}
	if useWinBoundedViewPool != want {
		t.Fatalf("useWinBoundedViewPool = %v, want %v on GOOS=%s", useWinBoundedViewPool, want, runtime.GOOS)
	}
	if runtime.GOOS != "windows" {
		resetWinBufferPoolsForTest()
		v := NewViewWithData([]byte("non-windows-sync-pool"))
		v.Release()
		if winViewPool.slots != nil {
			t.Fatalf("non-Windows Release should not allocate winViewPool.slots")
		}
		for i := range winChunkPools {
			if winChunkPools[i].slots != nil {
				t.Fatalf("non-Windows Release should not allocate winChunkPools[%d].slots", i)
			}
		}
	}
}

func TestWinBoundedChunkPoolsAllTiersQuotaReuseAndZeroing(t *testing.T) {
	origChunkFlag := useWinBoundedChunkPool
	useWinBoundedChunkPool = true
	defer func() {
		useWinBoundedChunkPool = origChunkFlag
		resetWinBufferPoolsForTest()
	}()
	resetWinBufferPoolsForTest()

	// Verify lazy initialization: nil before any Put, and still nil after Get on empty pool.
	for idx := 0; idx < numPools; idx++ {
		if winChunkPools[idx].slots != nil {
			t.Fatalf("tier %d slots not nil before first Put", idx)
		}
	}
	cLazy := newChunk(baseChunkSize)
	if winChunkPools[0].slots != nil {
		t.Fatalf("tier 0 slots should remain nil on Get when pool is empty")
	}
	cLazy.DecRef()
	if len(winChunkPools[0].slots) != 1 || cap(winChunkPools[0].slots) != winChunkPoolMaxSlots[0] {
		t.Fatalf("tier 0 lazy init failed: len=%d cap=%d want len=1 cap=%d",
			len(winChunkPools[0].slots), cap(winChunkPools[0].slots), winChunkPoolMaxSlots[0])
	}
	resetWinBufferPoolsForTest()

	// Test all 11 tiers (64B .. 64KiB): quota, overflow drop, LIFO reuse, slot root clearing, and zeroing.
	for idx := 0; idx < numPools; idx++ {
		chunkSize := baseChunkSize * (1 << idx)
		maxSlots := winChunkPoolMaxSlots[idx]
		overflow := 16
		total := maxSlots + overflow

		chunks := make([]*chunk, total)
		for i := 0; i < total; i++ {
			c := newChunk(chunkSize)
			if len(c.data) != chunkSize {
				t.Fatalf("tier %d chunk len=%d, want %d", idx, len(c.data), chunkSize)
			}
			// Fill with non-zero pattern to verify clear(c.data) on reuse.
			for j := range c.data {
				c.data[j] = 0xA5
			}
			chunks[i] = c
		}

		// Release all chunks: first maxSlots enter pool, remaining overflow drop c.data = nil.
		for i := 0; i < total; i++ {
			chunks[i].DecRef()
		}

		p := &winChunkPools[idx]
		if len(p.slots) != maxSlots {
			t.Fatalf("tier %d (%dB) pooled slots=%d, want maxSlots=%d", idx, chunkSize, len(p.slots), maxSlots)
		}
		for i := 0; i < maxSlots; i++ {
			if chunks[i].data == nil {
				t.Fatalf("tier %d pooled chunk %d should retain data slice", idx, i)
			}
		}
		for i := maxSlots; i < total; i++ {
			if chunks[i].data != nil {
				t.Fatalf("tier %d overflow chunk %d should have c.data == nil after DecRef", idx, i)
			}
		}

		// Pop top chunk: verify LIFO order, backing slot nilled out, data cleared, and refCount == 1.
		reused := newChunk(chunkSize)
		if reused != chunks[maxSlots-1] {
			t.Fatalf("tier %d expected LIFO reuse of last pooled chunk", idx)
		}
		if len(p.slots) != maxSlots-1 {
			t.Fatalf("tier %d len(slots)=%d after Get, want %d", idx, len(p.slots), maxSlots-1)
		}
		backing := p.slots[:cap(p.slots)]
		if backing[maxSlots-1] != nil {
			t.Fatalf("tier %d popped slot at index %d was not cleared to nil", idx, maxSlots-1)
		}
		if reused.ReadRefs() != 1 {
			t.Fatalf("tier %d reused chunk ReadRefs=%d, want 1", idx, reused.ReadRefs())
		}
		for j, b := range reused.data {
			if b != 0 {
				t.Fatalf("tier %d reused chunk byte %d = 0x%x, want 0x00", idx, j, b)
			}
		}
		reused.DecRef()
	}

	// Oversize (> MaxChunkSize) should never pool and should nil data on DecRef.
	oversize := newChunk(MaxChunkSize + 1024)
	if len(oversize.data) != MaxChunkSize+1024 {
		t.Fatalf("oversize len=%d", len(oversize.data))
	}
	oversize.DecRef()
	if oversize.data != nil {
		t.Fatalf("oversize chunk should nil data on DecRef")
	}
}

func TestWinBoundedViewPoolQuotaCloneAndRefLifecycle(t *testing.T) {
	origChunkFlag := useWinBoundedChunkPool
	origViewFlag := useWinBoundedViewPool
	useWinBoundedChunkPool = true
	useWinBoundedViewPool = true
	defer func() {
		useWinBoundedChunkPool = origChunkFlag
		useWinBoundedViewPool = origViewFlag
		resetWinBufferPoolsForTest()
	}()
	resetWinBufferPoolsForTest()

	// 1. Test View.Clone shared chunk refCount lifecycle: first Release must not destroy chunk.
	payload := []byte("shared-view-payload-test")
	v1 := NewViewWithData(payload)
	sharedChunk := v1.chunk
	if sharedChunk.ReadRefs() != 1 {
		t.Fatalf("initial chunk ReadRefs=%d, want 1", sharedChunk.ReadRefs())
	}
	v2 := v1.Clone()
	if v2.chunk != sharedChunk || sharedChunk.ReadRefs() != 2 {
		t.Fatalf("after Clone chunk ReadRefs=%d, want 2", sharedChunk.ReadRefs())
	}

	// Release v1: v1 is zeroed and pooled, but sharedChunk still has refCount == 1 and valid data.
	v1.Release()
	if v1.chunk != nil || v1.read != 0 || v1.write != 0 {
		t.Fatalf("v1 not zeroed on Release: %+v", *v1)
	}
	if sharedChunk.ReadRefs() != 1 {
		t.Fatalf("sharedChunk ReadRefs=%d after v1.Release, want 1", sharedChunk.ReadRefs())
	}
	if !bytes.Equal(v2.AsSlice(), payload) {
		t.Fatalf("v2 payload corrupted after v1.Release: got %q, want %q", v2.AsSlice(), payload)
	}
	if len(winChunkPools[0].slots) != 0 {
		t.Fatalf("sharedChunk should not enter chunk pool while v2 holds reference")
	}

	// Release v2: now sharedChunk reaches refCount == 0 and enters winChunkPools[0].
	v2.Release()
	if len(winChunkPools[0].slots) != 1 || winChunkPools[0].slots[0] != sharedChunk {
		t.Fatalf("sharedChunk should enter winChunkPools[0] after v2.Release")
	}

	resetWinBufferPoolsForTest()

	// 2. Test winViewPool quota (4096), ViewEntry clearing, and LIFO slot root clearing.
	const totalViews = winViewPoolMaxSlots + 500
	views := make([]*View, totalViews)
	var list ViewList
	for i := 0; i < totalViews; i++ {
		v := NewViewSize(64)
		list.PushBack(v)
		views[i] = v
	}
	for i := 0; i < totalViews; i++ {
		v := views[i]
		list.Remove(v)
		v.Release()
	}

	if len(winViewPool.slots) != winViewPoolMaxSlots {
		t.Fatalf("winViewPool len=%d, want %d", len(winViewPool.slots), winViewPoolMaxSlots)
	}
	for i, v := range views {
		if v.chunk != nil || v.read != 0 || v.write != 0 || v.Next() != nil || v.Prev() != nil {
			t.Fatalf("view %d not fully zeroed after Release: %+v", i, *v)
		}
	}

	topView := winViewPool.slots[winViewPoolMaxSlots-1]
	vReused := NewView(64)
	if vReused != topView {
		t.Fatalf("expected LIFO reuse from winViewPool")
	}
	if winViewPool.slots[:cap(winViewPool.slots)][winViewPoolMaxSlots-1] != nil {
		t.Fatalf("popped winViewPool slot was not cleared to nil")
	}
	vReused.Release()
}

func TestWinBoundedBufferPoolsConcurrentRace(t *testing.T) {
	origChunkFlag := useWinBoundedChunkPool
	origViewFlag := useWinBoundedViewPool
	useWinBoundedChunkPool = true
	useWinBoundedViewPool = true
	defer func() {
		useWinBoundedChunkPool = origChunkFlag
		useWinBoundedViewPool = origViewFlag
		resetWinBufferPoolsForTest()
	}()
	resetWinBufferPoolsForTest()

	var wg stdsync.WaitGroup
	sizes := []int{64, 128, 2048, 65536}
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				sz := sizes[(id+i)%len(sizes)]
				v := NewViewSize(sz)
				clone := v.Clone()
				// Write to v triggers copy-on-write chunk clone while clone holds a ref.
				_, _ = v.Write([]byte{byte(i)})
				clone.Release()
				v.Release()
			}
		}(g)
	}
	wg.Wait()
}
