package elevated

import "errors"

// Fixed pre-control exit ABI. Numeric phases contain no user data or raw error.
const (
	ExitValidate = 160 + iota
	ExitRecord
	ExitService
	ExitStderr
	ExitBind
	ExitBindingIdentity
	ExitCorePin
	ExitGUIPin
	ExitMedium
	ExitWorkspace
	ExitControl
)

type BootstrapError struct {
	Code int
	Err  error
}

func (e *BootstrapError) Error() string { return "fixed elevated bootstrap failed" }
func (e *BootstrapError) Unwrap() error { return e.Err }
func BootstrapExit(e error) int {
	var b *BootstrapError
	if errors.As(e, &b) && b.Code >= ExitValidate && b.Code <= ExitControl {
		return b.Code
	}
	return 1
}
func ControlName(lease string) string       { return `\\.\pipe\KatClient-core-` + lease }
func PrivateStderrName(lease string) string { return `\\.\pipe\KatClient-stderr-` + lease }
