package procattr

import (
	"context"
	"time"
)

const tupleBudget = 20 * time.Millisecond

var tupleSlots = make(chan struct{}, 4)

// LookupTuple accepts only the trusted in-core original tuple. Native table
// APIs cannot be canceled mid-syscall: the slot stays owned until they return,
// while forwarding receives unknown within budget.
func LookupTuple(ctx context.Context, q Query) Identity {
	if ctx.Err() != nil {
		return unavailableIdentity("unknown")
	}
	if id, ok := cachedUDPTuple(q); ok {
		return id
	}
	id := budgetTuple(ctx, q, lookupLocal)
	storeUDPTuple(q, id)
	return id
}
func budgetTuple(ctx context.Context, q Query, lookup func(context.Context, Query) Identity) Identity {
	if ctx.Err() != nil {
		return unavailableIdentity("unknown")
	}
	select {
	case tupleSlots <- struct{}{}:
	default:
		return unavailableIdentity("unknown")
	}
	child, cancel := context.WithTimeout(ctx, tupleBudget)
	defer cancel()
	deadline, _ := child.Deadline()
	result := make(chan Identity, 1)
	go func() { defer func() { <-tupleSlots }(); result <- lookup(child, q) }()
	select {
	case id := <-result:
		if child.Err() == nil && time.Now().Before(deadline) {
			return withoutProcessEvidence(id)
		}
	case <-child.Done():
	}
	return unavailableIdentity("unknown")
}
