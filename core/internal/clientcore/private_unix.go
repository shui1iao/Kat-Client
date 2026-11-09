//go:build !windows

package clientcore

import (
	"github.com/shui1iao/Kat/internal/userio"
)

func secureWorkspace(path string) error { return userio.Chmod(path, 0700) }
func secureFile(path string) error      { return userio.Chmod(path, 0600) }

func rejectReparse(path string) error { return nil }
