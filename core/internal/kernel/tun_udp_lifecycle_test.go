package kernel

import (
	"context"
	"github.com/shui1iao/Kat/internal/tunstack"
	"testing"
	"time"
)

func TestTUNOneAssociationSlotIsOneUsableMapping(t *testing.T) {
	s := c50Server(t, nil, func(c *Config) { c.Limits.UDPAssociations = 1 })
	u := m2State(t, s)
	var pcs []*m2Packet
	s.rt.nodes["direct"] = m2Outbound{Outbound: s.rt.nodes["direct"], pcs: &pcs}
	_, ctx, end, err := c50Ingress(t, s).begin(context.Background(), u.t, u.c, tunstack.UDP)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		u.closePC()
		u.pcWG.Wait()
		end()
		if n := s.udpSlots.inUse(); n != 0 {
			t.Error("source slot leaked", n)
		}
	}()
	if n := s.udpSlots.inUse(); n != 1 || s.connSlots.inUse() != 0 {
		t.Fatal("source missing UDP reservation or charged TCP", n)
	}
	target := Address{"203.0.113.60", 4444}
	first := tunNATKey{"direct", -1, u.t.Epoch, "standalone"}
	second := first
	second.rule = 1
	v, err := u.session(ctx, first, target)
	if err != nil || s.udpSlots.inUse() != 1 {
		t.Fatal("first mapping denied", err)
	}
	if _, err := u.session(ctx, second, target); err == nil {
		t.Fatal("second mapping bypassed limit")
	}
	v.close()
	u.pcWG.Wait()
	if n := s.udpSlots.inUse(); n != 1 {
		t.Fatal("source reservation lost", n)
	}
	if _, err := u.session(ctx, second, target); err != nil {
		t.Fatal("released slot unavailable", err)
	}
}
func TestTUNQueuedUDPCannotMoveToNewPhysicalEpoch(t *testing.T) {
	for _, mode := range []string{"before-open", "before-write"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			s := c50Server(t, nil, func(c *Config) {
				c.SetClientEgress(&ClientEgress{UDPBinding: func(bool) (uint64, string, error) {
					calls++
					if mode == "before-write" && calls == 1 {
						return 44, "old", nil
					}
					return 45, "new", nil
				}})
			})
			var pcs []*m2Packet
			s.rt.nodes["direct"] = m2Outbound{Outbound: s.rt.nodes["direct"], pcs: &pcs}
			u := m2State(t, s)
			u.send(u.a.ctx, packet{Address{"203.0.113.60", 4444}, []byte("queued")}, time.Second)
			if mode == "before-open" {
				if calls != 1 || len(pcs) != 0 {
					t.Fatal("stale payload created mapping", calls, len(pcs))
				}
				return
			}
			if calls != 2 || len(pcs) != 1 {
				t.Fatal("missing last binding check", calls, len(pcs))
			}
			select {
			case <-pcs[0].written:
				t.Fatal("payload crossed epoch")
			default:
			}
			u.pcWG.Wait()
			if pcs[0].closes.Load() != 1 {
				t.Fatal("stale mapping leaked")
			}
		})
	}
}
