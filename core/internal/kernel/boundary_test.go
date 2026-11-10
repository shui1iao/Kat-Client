package kernel

import (
	"bytes"

	"testing"
)

func TestDatagramTypeEnumerations(t *testing.T) {
	for _, raw := range [][]byte{{2}, {1, 127}, {3, 0}, {4, 1, 2}} {
		if _, e := readAddress(bytes.NewReader(raw)); e == nil {
			t.Fatal("bad address accepted")
		}
	}
}
