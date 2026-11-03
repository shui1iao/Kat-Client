//go:build !windows

package clientcore

import "os"

func secureWorkspace(path string) error { return os.Chmod(path, 0700) }
func secureFile(path string) error      { return os.Chmod(path, 0600) }

func rejectReparse(path string) error { return nil }
