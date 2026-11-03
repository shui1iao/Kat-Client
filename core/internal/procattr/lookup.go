// Package procattr accepts only actual local socket tuples or the private
// SYSTEM bridge registration channel. No proxy header is an identity source.
package procattr

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
)

type Query struct {
	Network                                                        string
	Source, Destination, ControlSource, ControlDestination, Target netip.AddrPort
}
type Identity struct {
	SourceAddr  string `json:"-"`
	InboundKind string `json:"-"`
	Name        string `json:"name"`
	Path        string `json:"path,omitempty"`
	Status      string `json:"status"`
	PID         uint32 `json:"pid,omitempty"`
	Stamp       uint64 `json:"stamp,omitempty"`
}
type Row struct {
	Source, Destination netip.AddrPort
	PID                 uint32
}

func unique(rows []Row, q Query) (uint32, string) {
	var pid uint32
	count := 0
	for _, r := range rows {
		match := r.Source == q.Source
		if q.Network == "udp" {
			match = r.Source.Port() == q.Source.Port() && r.Source.Addr().Is4() == q.Source.Addr().Is4() && (r.Source.Addr() == q.Source.Addr() || r.Source.Addr().IsUnspecified())
		} else {
			match = match && r.Destination == q.Destination
		}
		if match {
			count++
			pid = r.PID
		}
	}
	if count > 1 {
		return 0, "ambiguous"
	}
	if count == 0 || pid == 0 {
		return 0, "closed"
	}
	return pid, "known"
}

// Origin belongs to one accepted HTTP connection and is never shared through
// headers. Its TCP owner is loaded lazily once while that socket is alive.
type Origin struct {
	query    Query
	once     sync.Once
	identity Identity
}

func NewOrigin(source, destination net.Addr) *Origin {
	return &Origin{query: Query{Network: "tcp", Source: Addr(source), Destination: Addr(destination)}}
}
func (o *Origin) lookup(ctx context.Context) Identity {
	o.once.Do(func() { o.identity = lookupLocal(ctx, o.query) })
	return o.identity
}

type key struct{ source, destination netip.AddrPort }

var httpFlows struct {
	sync.Mutex
	m map[key]*Origin
}

func RegisterHTTP(c net.Conn, o *Origin) net.Conn {
	if o == nil {
		return c
	}
	k := key{Addr(c.LocalAddr()), Addr(c.RemoteAddr())}
	httpFlows.Lock()
	if httpFlows.m == nil {
		httpFlows.m = map[key]*Origin{}
	}
	httpFlows.m[k] = o
	httpFlows.Unlock()
	return &httpConn{Conn: c, k: k, o: o}
}

type httpConn struct {
	net.Conn
	k    key
	o    *Origin
	once sync.Once
	err  error
}

func (c *httpConn) Close() error {
	c.once.Do(func() {
		httpFlows.Lock()
		if httpFlows.m[c.k] == c.o {
			delete(httpFlows.m, c.k)
		}
		httpFlows.Unlock()
		c.err = c.Conn.Close()
	})
	return c.err
}
func (c *httpConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}
func (c *httpConn) CloseRead() error {
	if v, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return v.CloseRead()
	}
	return nil
}
func httpIdentity(ctx context.Context, q Query) (Identity, bool) {
	httpFlows.Lock()
	o := httpFlows.m[key{q.ControlSource, q.ControlDestination}]
	httpFlows.Unlock()
	if o == nil {
		return Identity{}, false
	}
	return o.lookup(ctx), true
}
func Addr(a net.Addr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	v, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(v.Addr().Unmap(), v.Port())
}

// resolveCurrent is shared by the native adapter and injected-system tests.
// The proof holds a process handle until the second owner snapshot completes.
func resolveCurrent(q Query, rows func(Query) ([]Row, string), prove func(uint32) (Identity, func() bool, func())) Identity {
	first, status := rows(q)
	if status != "known" {
		return Identity{Status: status}
	}
	pid, status := unique(first, q)
	if status != "known" {
		return Identity{Status: status}
	}
	id, valid, close := prove(pid)
	if close != nil {
		defer close()
	}
	if id.Status != "known" {
		return id
	}
	second, status := rows(q)
	pid2, state := unique(second, q)
	if status != "known" || state != "known" || pid2 != pid || valid == nil || !valid() {
		return Identity{PID: pid, Status: "changed"}
	}
	return id
}

type servicePeer struct {
	scmPID, pipePID uint32
	before, after   uint64
	systemSID       string
	session         uint32
	image, expected string
	running, alive  bool
}

func trustedService(p servicePeer) bool {
	return p.scmPID != 0 && p.scmPID == p.pipePID && p.before != 0 && p.before == p.after && p.systemSID == "S-1-5-18" && p.session == 0 && strings.EqualFold(p.image, p.expected) && p.running && p.alive
}
