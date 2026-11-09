//go:build !windows

package tunplatform

import "errors"

func platformOS(Launch) (osBackend, error) { return nil, errors.New("TUN_PLATFORM_UNSUPPORTED") }
