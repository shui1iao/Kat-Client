package kernel

import (
	"context"
	"fmt"
	"github.com/shui1iao/Kat/internal/outbound/group"
)

// ClientApplySelections changes preferences on the existing generation. All
// targets are admitted before any change; listeners, DNS, probes and flows are
// not replaced. The caller owns the source-file transaction and flow policy.
func (s *Server) ClientApplySelections(ctx context.Context, changes []GroupConfig) error {
	k := s.core
	k.reloadMu.Lock()
	defer k.reloadMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	current := s.current()
	type edit struct {
		g                  group.Group
		name, member, kind string
	}
	edits := []edit{}
	for _, gc := range changes {
		var target group.Group
		for _, g := range current.rt.groups {
			if g.Name() == gc.Name {
				target = g
				break
			}
		}
		if target == nil {
			return fmt.Errorf("group unavailable")
		}
		member := gc.Fixed
		if gc.Type == group.TypeSelect {
			member = gc.Selected
			if member == "" && len(target.Members()) > 0 {
				member = target.Members()[0]
			}
		}
		if member != "" && !contains(target.Members(), member) {
			return fmt.Errorf("member unavailable")
		}
		if gc.Type == group.TypeSelect {
			if _, ok := target.(group.Selector); !ok {
				return fmt.Errorf("not select")
			}
		} else {
			if _, ok := target.(interface{ SetFixed(string) error }); !ok {
				return fmt.Errorf("not automatic")
			}
		}
		edits = append(edits, edit{target, gc.Name, member, gc.Type})
	}
	// There can be no cancellation/error after admission: finish the accepted
	// mutation, rather than expose a partially switched batch as canceled.
	for _, e := range edits {
		if e.kind == group.TypeSelect {
			_ = e.g.(group.Selector).Select(e.member)
			k.selMu.Lock()
			k.selections[e.name] = selRecord{Selected: e.member, Config: e.member}
			k.selMu.Unlock()
		} else {
			_ = e.g.(interface{ SetFixed(string) error }).SetFixed(e.member)
		}
	}
	return nil
}
