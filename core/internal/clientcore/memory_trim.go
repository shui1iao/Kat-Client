package clientcore

import (
	"runtime"
	"runtime/debug"
	"runtime/metrics"

	anytlsout "github.com/shui1iao/Kat/internal/outbound/anytls"
	"github.com/shui1iao/Kat/internal/udpmmsg"
)

// readRuntimeMemoryBreakdown collects Go runtime memory classes via
// runtime/metrics without triggering a stop-the-world pause on 1s status polls.
func readRuntimeMemoryBreakdown() map[string]uint64 {
	samples := [...]metrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/heap/unused:bytes"},
		{Name: "/memory/classes/heap/free:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
		{Name: "/memory/classes/heap/stacks:bytes"},
		{Name: "/memory/classes/total:bytes"},
	}
	metrics.Read(samples[:])
	u := func(i int) uint64 {
		if samples[i].Value.Kind() == metrics.KindUint64 {
			return samples[i].Value.Uint64()
		}
		return 0
	}
	objects := u(0)
	unused := u(1)
	free := u(2)
	released := u(3)
	return map[string]uint64{
		"heap_alloc":    objects,
		"heap_inuse":    objects + unused,
		"heap_idle":     free + released,
		"heap_released": released,
		"stack_inuse":   u(4),
		"sys":           u(5),
		"goroutines":    uint64(runtime.NumGoroutine()),
	}
}

// TrimMemory releases idle pooled buffers across the active kernel generation,
// AnyTLS receive buffer pool, and UDP batch pools so the runtime scavenger
// can return spans to the OS.
func (h *Host) TrimMemory() int {
	dropped := anytlsout.TrimRecvBufPool() + udpmmsg.TrimPool()
	if h == nil {
		return dropped
	}
	h.mu.Lock()
	s := h.server
	h.mu.Unlock()
	idle := true
	if s != nil {
		dropped += s.TrimBuffers()
		idle = s.ActiveTraffic() == 0
	}
	if idle {
		debug.FreeOSMemory()
		trimOSWorkingSet()
	}
	return dropped
}
