//go:build !windows

package procattr

import "context"

func lookupLocal(context.Context, Query) Identity { return Identity{Status: "unsupported"} }
func Lookup(context.Context, Query) Identity      { return Identity{Status: "unsupported"} }
