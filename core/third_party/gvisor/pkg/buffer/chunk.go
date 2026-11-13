// Copyright 2022 The gVisor Authors.
// Modified by Kat Authors: bound idle chunk pools on Windows.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package buffer

import (
	"fmt"
	"runtime"
	stdsync "sync"

	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// This is log2(baseChunkSize). This number is used to calculate which pool
	// to use for a payload size by right shifting the payload size by this
	// number and passing the result to MostSignificantOne64.
	baseChunkSizeLog2 = 6

	// This is the size of the buffers in the first pool. Each subsequent pool
	// creates payloads 2^(pool index) times larger than the first pool's
	// payloads.
	baseChunkSize = 1 << baseChunkSizeLog2 // 64

	// MaxChunkSize is largest payload size that we pool. Payloads larger than
	// this will be allocated from the heap and garbage collected as normal.
	MaxChunkSize = baseChunkSize << (numPools - 1) // 64k

	// The number of chunk pools we have for use.
	numPools = 11
)

// chunkPools is a collection of pools for payloads of different sizes. The
// size of the payloads doubles in each successive pool.
var chunkPools [numPools]sync.Pool

var winChunkPoolMaxSlots = [numPools]int{
	512,  // 0: 64B    (32 KiB)
	2048, // 1: 128B   (256 KiB)
	256,  // 2: 256B   (64 KiB)
	256,  // 3: 512B   (128 KiB)
	128,  // 4: 1KiB   (128 KiB)
	512,  // 5: 2KiB   (1 MiB)
	64,   // 6: 4KiB   (256 KiB)
	32,   // 7: 8KiB   (256 KiB)
	32,   // 8: 16KiB  (512 KiB)
	32,   // 9: 32KiB  (1 MiB)
	48,   // 10: 64KiB (3 MiB)
}

type boundedChunkPool struct {
	mu    stdsync.Mutex
	slots []*chunk
}

var (
	useWinBoundedChunkPool = runtime.GOOS == "windows"
	winChunkPools          [numPools]boundedChunkPool
)

func init() {
	for i := 0; i < numPools; i++ {
		chunkSize := baseChunkSize * (1 << i)
		chunkPools[i].New = func() any {
			return &chunk{
				data: make([]byte, chunkSize),
			}
		}
	}
}

// Precondition: 0 <= size <= maxChunkSize
func getChunkPoolIdx(size int) int {
	idx := 0
	if size > baseChunkSize {
		idx = bits.MostSignificantOne64(uint64(size) >> baseChunkSizeLog2)
		if size > 1<<(idx+baseChunkSizeLog2) {
			idx++
		}
	}
	if idx >= numPools {
		panic(fmt.Sprintf("pool for chunk size %d does not exist", size))
	}
	return idx
}

// Precondition: 0 <= size <= maxChunkSize
func getChunkPool(size int) *sync.Pool {
	return &chunkPools[getChunkPoolIdx(size)]
}

// Chunk represents a slice of pooled memory.
//
// +stateify savable
type chunk struct {
	chunkRefs
	data []byte
}

func newChunk(size int) *chunk {
	var c *chunk
	if size > MaxChunkSize {
		c = &chunk{
			data: make([]byte, size),
		}
	} else if useWinBoundedChunkPool {
		idx := getChunkPoolIdx(size)
		p := &winChunkPools[idx]
		p.mu.Lock()
		if n := len(p.slots); n > 0 {
			c = p.slots[n-1]
			p.slots[n-1] = nil
			p.slots = p.slots[:n-1]
		}
		p.mu.Unlock()
		if c == nil {
			chunkSize := baseChunkSize * (1 << idx)
			c = &chunk{
				data: make([]byte, chunkSize),
			}
		} else {
			clear(c.data)
		}
	} else {
		pool := getChunkPool(size)
		c = pool.Get().(*chunk)
		clear(c.data)
	}
	c.InitRefs()
	return c
}

func (c *chunk) destroy() {
	if len(c.data) > MaxChunkSize {
		c.data = nil
		return
	}
	if useWinBoundedChunkPool {
		idx := getChunkPoolIdx(len(c.data))
		if len(c.data) != baseChunkSize*(1<<idx) {
			c.data = nil
			return
		}
		maxSlots := winChunkPoolMaxSlots[idx]
		p := &winChunkPools[idx]
		p.mu.Lock()
		if len(p.slots) < maxSlots {
			if p.slots == nil {
				p.slots = make([]*chunk, 0, maxSlots)
			}
			p.slots = append(p.slots, c)
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()
		c.data = nil
		return
	}
	pool := getChunkPool(len(c.data))
	pool.Put(c)
}

func (c *chunk) DecRef() {
	c.chunkRefs.DecRef(c.destroy)
}

func (c *chunk) Clone() *chunk {
	cpy := newChunk(len(c.data))
	copy(cpy.data, c.data)
	return cpy
}
