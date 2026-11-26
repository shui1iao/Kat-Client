//go:build !windows && !linux

package procattr

import "context"

func lookupLocal(context.Context, Query) Identity { return Identity{Status: "unsupported"} }
func Lookup(context.Context, Query) Identity      { return Identity{Status: "unsupported"} }
func cachedUDPTuple(Query) (Identity, bool)       { return Identity{}, false }
func storeUDPTuple(Query, Identity)               {}
