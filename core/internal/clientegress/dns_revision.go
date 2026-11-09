package clientegress

import (
	"context"
	"errors"
	"net"
	"reflect"
)

type dnsRevision struct {
	options  Options
	number   uint64
	life     context.Context
	cancel   context.CancelFunc
	resolver *net.Resolver
}

func (p *Policy) installDNS(o Options, number uint64) {
	life, cancel := context.WithCancel(context.Background())
	next := &dnsRevision{options: o.Clone(), number: number, life: life, cancel: cancel}
	next.resolver = &net.Resolver{PreferGo: true, StrictErrors: true, Dial: p.resolverConn}
	old := p.dns.Swap(next)
	if old != nil {
		old.cancel()
	}
}
func (p *Policy) DNSSnapshot() (Options, uint64) {
	s := p.dns.Load()
	return s.options.Clone(), s.number
}
func (p *Policy) DNSContext(ctx context.Context) (context.Context, func(), uint64) {
	s := p.dns.Load()
	child, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.life, cancel)
	if s.life.Err() != nil {
		cancel()
	}
	return child, func() { stop(); cancel() }, s.number
}
func (p *Policy) RefreshDNS(o Options, number uint64) error {
	if !p.Ready() {
		return errors.New("physical lease unavailable")
	}
	old := p.dns.Load()
	if number == old.number && o.Fingerprint == old.options.Fingerprint {
		return nil
	}
	if number <= old.number || o.Schema != Schema || o.Identity != p.Options.Identity || !reflect.DeepEqual(o.IPv4, p.Options.IPv4) || !reflect.DeepEqual(o.IPv6, p.Options.IPv6) || !reflect.DeepEqual(o.LUID4, p.Options.LUID4) || !reflect.DeepEqual(o.LUID6, p.Options.LUID6) {
		p.Fail()
		return errors.New("DNS refresh changed physical identity")
	}
	// Full OS membership/bounds validation, without replacing this business policy.
	checked, e := newPolicy(o, p.bind, platformValidate)
	if e != nil {
		p.Fail()
		return e
	}
	checked.dns.Load().cancel()
	p.installDNS(o, number)
	return nil
}
