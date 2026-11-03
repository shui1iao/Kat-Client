//go:build !windows

package procattr

import (
	"context"
	"testing"
)

func TestUnsupportedPlatformNeverInventsIdentity(t *testing.T) {
	id := Lookup(context.Background(), Query{Network: "tcp", Source: ap("127.0.0.1:1234"), Destination: ap("127.0.0.1:7891")})
	if id.Status != "unsupported" || id.Name != "" {
		t.Fatal(id)
	}
}
