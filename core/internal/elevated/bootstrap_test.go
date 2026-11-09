package elevated

import (
	"errors"
	"strings"
	"testing"
)

func TestBootstrapFiniteExitAndPipeNames(t *testing.T) {
	for code := ExitValidate; code <= ExitControl; code++ {
		if BootstrapExit(&BootstrapError{Code: code, Err: ErrIdentity}) != code {
			t.Fatal("lost phase", code)
		}
	}
	if BootstrapExit(errors.New("private message")) != 1 || BootstrapExit(&BootstrapError{Code: 200, Err: ErrIdentity}) != 1 {
		t.Fatal("invented phase")
	}
	lease := strings.Repeat("a", 64)
	if ControlName(lease) != `\\.\pipe\KatClient-core-`+lease || PrivateStderrName(lease) != `\\.\pipe\KatClient-stderr-`+lease {
		t.Fatal("wire namespace mismatch")
	}
}
