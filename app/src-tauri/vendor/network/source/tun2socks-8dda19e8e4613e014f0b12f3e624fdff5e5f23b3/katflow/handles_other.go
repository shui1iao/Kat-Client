//go:build !windows

package katflow

import (
	"errors"
	"time"
)

func openHandles() error      { return errors.New("Kat inherited flow channel requires Windows") }
func readACK(time.Time) error { return errors.New("unsupported") }
