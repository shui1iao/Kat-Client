//go:build !windows

package procattr

import (
	"context"
	"encoding/json"
	"errors"
)

func TrustedDNSRevision(context.Context, uint64, string) (json.RawMessage, error) {
	return nil, errors.New("unsupported")
}
