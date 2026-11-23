package group

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"net"
	"testing"
)

type scopeProbe struct {
	outbound.Outbound
	seen chan bool
}

func (p *scopeProbe) Name() string { return "direct" }
func (p *scopeProbe) Type() string { return "direct" }
func (p *scopeProbe) DialTCP(c context.Context, _ outbound.Addr) (net.Conn, error) {
	p.seen <- outbound.PublicTargetOnly(c)
	return nil, errors.New("offline witness")
}
func TestSubscriptionProbeScopeReachesMember(t *testing.T) {
	for _, public := range []bool{true, false} {
		member := &scopeProbe{seen: make(chan bool, 1)}
		g, e := New(Options{Name: "grp", Type: TypeURLTest, Members: []string{"direct"}, Probe: &ProbeOptions{URL: "http://fixture.invalid/status", PublicDirectOnly: public, ClientHead: true}}, []outbound.Outbound{member}, nil)
		if e != nil {
			t.Fatal(e)
		}
		_, err := g.(*autoGroup).probe(context.Background(), member)
		if err == nil || <-member.seen != public {
			t.Fatal("wrong target scope")
		}
		g.Close()
	}
}
