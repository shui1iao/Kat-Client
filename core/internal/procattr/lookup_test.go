package procattr

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
func TestCurrentOwnerIPv4IPv6AndUDPReuse(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, family := range []struct{ src, dst string }{{"192.0.2.1:1234", "1.1.1.1:443"}, {"[2001:db8::1]:1234", "[2606:4700:4700::1111]:443"}} {
			q := Query{Network: network, Source: ap(family.src), Destination: ap(family.dst)}
			pid := uint32(10)
			alive := true
			stamp := uint64(100)
			rows := func(Query) ([]Row, string) {
				return []Row{{Source: q.Source, Destination: q.Destination, PID: pid}}, "known"
			}
			prove := func(p uint32) (Identity, func() bool, func()) {
				created := stamp
				return Identity{Name: map[uint32]string{10: "a.exe", 11: "b.exe"}[p], Status: "known", PID: p, Stamp: created}, func() bool { return alive && stamp == created }, func() {}
			}
			id := resolveCurrent(q, rows, prove)
			if id.Name != "a.exe" {
				t.Fatal(id)
			}
			pid = 11
			stamp = 101
			id = resolveCurrent(q, rows, prove)
			if id.Name != "b.exe" {
				t.Fatal("old live process port reused", id)
			}
			calls := 0
			changing := func(q Query) ([]Row, string) {
				calls++
				if calls == 2 {
					pid = 10
				}
				return rows(q)
			}
			id = resolveCurrent(q, changing, prove)
			if id.Status != "changed" {
				t.Fatal(id)
			}
			alive = false
			id = resolveCurrent(q, rows, prove)
			if id.Status != "changed" {
				t.Fatal(id)
			}
		}
	}
}
func TestCurrentOwnerRejectsAmbiguityPermissionsAndPIDReuse(t *testing.T) {
	q := Query{Network: "udp", Source: ap("127.0.0.1:1234")}
	row := Row{Source: q.Source, PID: 10}
	for _, rows := range [][]Row{{row, row}, {row, {Source: ap("0.0.0.0:1234"), PID: 11}}} {
		if _, s := unique(rows, q); s != "ambiguous" {
			t.Fatal(s)
		}
	}
	denied := func(Query) ([]Row, string) { return nil, "denied" }
	id := resolveCurrent(q, denied, func(uint32) (Identity, func() bool, func()) {
		t.Fatal("unexpected process query")
		return Identity{}, nil, nil
	})
	if id.Status != "denied" {
		t.Fatal(id)
	}
	rows := func(Query) ([]Row, string) { return []Row{row}, "known" }
	id = resolveCurrent(q, rows, func(uint32) (Identity, func() bool, func()) {
		return Identity{Name: "x", Status: "known", PID: 10, Stamp: 1}, func() bool { return false }, func() {}
	})
	if id.Status != "changed" {
		t.Fatal(id)
	}
}
func TestHTTPRegistryOnlyExactSocketAndCleanup(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	o := NewOrigin(c.LocalAddr(), c.RemoteAddr())
	o.once.Do(func() { o.identity = Identity{Name: "app.exe", Status: "known", PID: 7, Stamp: 8} })
	wrapped := RegisterHTTP(c, o)
	q := Query{ControlSource: Addr(c.LocalAddr()), ControlDestination: Addr(c.RemoteAddr())}
	id, ok := httpIdentity(context.Background(), q)
	if !ok || id.Name != "app.exe" {
		t.Fatal(id, ok)
	}
	q.ControlSource = ap("127.0.0.1:1")
	if _, ok = httpIdentity(context.Background(), q); ok {
		t.Fatal("forged tuple accepted")
	}
	wrapped.Close()
	q.ControlSource = Addr(c.LocalAddr())
	if _, ok = httpIdentity(context.Background(), q); ok {
		t.Fatal("stale socket mapping")
	}
}

func TestTrustedServiceRejectsForgedPeer(t *testing.T) {
	base := servicePeer{scmPID: 1, pipePID: 1, before: 10, after: 10, systemSID: "S-1-5-18", session: 0, image: "installed", expected: "installed", running: true, alive: true}
	if !trustedService(base) {
		t.Fatal("valid denied")
	}
	for i := 0; i < 8; i++ {
		p := base
		switch i {
		case 0:
			p.pipePID = 2
		case 1:
			p.after = 11
		case 2:
			p.systemSID = "S-1-5-21-1"
		case 3:
			p.session = 1
		case 4:
			p.image = "untrusted"
		case 5:
			p.running = false
		case 6:
			p.alive = false
		case 7:
			p.scmPID = 0
		}
		if trustedService(p) {
			t.Fatal("forged peer", i)
		}
	}
}

func TestInstallationAuthorityParityFailClosed(t *testing.T) {
	owner := "S-1-5-18"
	user := "S-1-5-32-545"
	for _, mask := range []uint32{0x10000000, 0x40000000, 0x40000, 0x80000, 0x10000, 2, 4, 0x20} {
		if safeGrant(owner, user, mask, 0, "registry", true, false) {
			t.Fatal("unsafe registry", mask)
		}
	}
	if !safeGrant(owner, user, 0x20019, 0, "registry", true, false) || !safeGrant(owner, "S-1-3-0", 0xf003f, 2, "registry", false, false) || safeGrant(owner, "S-1-3-0", 0xf003f, 2, "registry", true, false) {
		t.Fatal("creator template too broad")
	}
	if safeGrant(owner, user, 0x116, 0, "ancestor", false, false) {
		t.Fatal("writable ProgramData ancestor")
	}
	if !safeGrant(owner, "S-1-3-0", 0x10000000, 8, "ancestor", false, false) {
		t.Fatal("inherit only")
	}
	if safeGrant("S-1-5-21-1", owner, 0, 0, "ancestor", false, false) {
		t.Fatal("untrusted owner")
	}
	for _, p := range []string{`C:\Kat Client Test`, `D:\Applications\客户端`} {
		if !validRoot(p) {
			t.Fatal(p)
		}
	}
	for _, p := range []string{`C:\`, `C:relative`, `\\server\share\Kat`, `\\?\C:\Kat`, `C:\foo\..\Kat`, `C:\foo.\Kat`, `C:\foo:stream`, `C:\COM1.txt\Kat`, `C:/Kat`} {
		if validRoot(p) {
			t.Fatal(p)
		}
	}
	if !validUserSID("S-1-5-21-1-2-3-1000") || validUserSID("S-1-5-18") || validUserSID("S-1-5-21-01-2-3-1000") {
		t.Fatal("SID authority")
	}
}

func TestExactTupleSameDestinationAndConcurrentRegistry(t *testing.T) {
	q := Query{Network: "tcp", Source: ap("127.0.0.1:20000"), Destination: ap("1.1.1.1:443")}
	rows := []Row{{Source: q.Source, Destination: q.Destination, PID: 1}, {Source: ap("127.0.0.1:20001"), Destination: q.Destination, PID: 2}}
	pid, state := unique(rows, q)
	if pid != 1 || state != "known" {
		t.Fatal(pid, state)
	}
	q.Source = rows[1].Source
	pid, state = unique(rows, q)
	if pid != 2 || state != "known" {
		t.Fatal(pid, state)
	}
	c, peer := net.Pipe()
	defer peer.Close()
	o := NewOrigin(nil, nil)
	o.once.Do(func() { o.identity = Identity{Name: "app.exe", Status: "known"} })
	wrapped := RegisterHTTP(c, o)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				httpIdentity(context.Background(), Query{})
			}
		}()
	}
	wrapped.Close()
	wg.Wait()
}
