package procattr

import "errors"

var ErrRevisionChanged = errors.New("trusted network revision superseded")

func IsRevisionChanged(e error) bool { return errors.Is(e, ErrRevisionChanged) }
