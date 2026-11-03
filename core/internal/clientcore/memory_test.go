package clientcore

import (
	"runtime"
	"testing"
)

func TestProcessMemoryBytesReportsOwnProcess(t *testing.T) {
	mem, ok := processMemoryBytes()
	if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
		if !ok || mem == 0 {
			t.Fatalf("expected own process memory, got %d ok=%v", mem, ok)
		}
	}
}
