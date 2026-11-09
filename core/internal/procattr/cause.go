package procattr

import (
	"errors"
	"syscall"
)

// Fixed vocabulary only. No path, request bytes, PID, or native error string.
var causes = [...]string{"local_denied", "not_bridged", "pin", "scm", "pipe_open", "pipe_identity", "session_hello", "session_timeout", "session_closed", "session_backoff", "service:FLOW_NOT_ACTIVE", "service:FLOW_QUERY", "service:FLOW_UNAVAILABLE", "service:LEASE_CHANGED", "service:CALLER_DENIED", "service:INSTALL_RELAUNCH_REQUIRED", "process:denied", "process:closed", "process:changed", "process:ambiguous", "process:unknown", "process:unsupported"}

func SafeCause(s string) string {
	for _, v := range causes {
		if s == v {
			return s
		}
	}
	return "process:unknown"
}

type AttributionError struct {
	Cause string
	Win32 uint32
}

func (e *AttributionError) Error() string {
	return "trusted original-flow attribution unavailable: " + SafeCause(e.Cause)
}
func attributionError(cause string, err error) error {
	var code syscall.Errno
	_ = errors.As(err, &code)
	var prior *AttributionError
	if code == 0 && errors.As(err, &prior) {
		return &AttributionError{SafeCause(cause), prior.Win32}
	}
	return &AttributionError{SafeCause(cause), uint32(code)}
}
func failureIdentity(err error) Identity {
	var e *AttributionError
	if errors.As(err, &e) {
		return Identity{Status: "denied", Cause: SafeCause(e.Cause), Win32: e.Win32}
	}
	return Identity{Status: "denied", Cause: "session_closed"}
}
