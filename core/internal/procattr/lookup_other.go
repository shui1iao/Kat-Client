//go:build !windows

package procattr

import "context"

func lookupLocal(context.Context, Query) Identity { return Identity{Status: "unsupported"} }
func Lookup(context.Context, Query) Identity      { return Identity{Status: "unsupported"} }

// LookupTuple is only for trusted in-process original packet tuples. It does
// not consult proxy control sockets, HTTP registries or retired bridge leases.
