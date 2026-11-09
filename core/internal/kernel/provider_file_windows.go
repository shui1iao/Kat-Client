package kernel

import (
	"github.com/shui1iao/Kat/internal/userio"
	"os"
)

func openProviderFile(path string) (*os.File, error) { return userio.Open(path) }
