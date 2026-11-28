package procattr

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestC50RetiredSessionIdentityFence(t *testing.T) {
	// Epoch zero only bypasses the retired bridge fence; it is NOT a replacement
	// for lookupLocal/resolveCurrent's PID, path and process-creation proof.
	ordinary := Identity{Name: "ordinary.exe", Path: `C:\Apps\ordinary.exe`, Status: "known", PID: 42, Stamp: 100}
	before := ordinary
	if !IdentityCurrent(ordinary) || ordinary != before {
		t.Fatal("ordinary identity altered or rejected")
	}
	for _, epoch := range []uint64{1, 2, 0xffff, 1 << 63, ^uint64(0)} {
		old := ordinary
		old.SessionEpoch = epoch
		if IdentityCurrent(old) {
			t.Fatalf("retired bridge identity accepted: epoch=%d", epoch)
		}
	}
}

func TestC50LookupTupleCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	q := Query{Network: "udp", Source: netip.MustParseAddrPort("127.0.0.1:45000"), Destination: netip.MustParseAddrPort("203.0.113.50:443")}
	got := LookupTuple(ctx, q)
	// The common budget rejects cancellation before platform/native lookup.
	if got.Status != "unknown" || got.Cause != "process:unknown" || got.SessionEpoch != 0 || got.Name != "" {
		t.Fatalf("tuple lookup used stale proxy/session identity: %+v", got)
	}
}

func TestRound2HTTPOriginalTuple(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	a, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	b, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	origin := NewOrigin(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 45001}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080})
	c := RegisterHTTP(a, origin)
	defer c.Close()
	src, kind := FlowOrigin(context.Background(), Query{ControlSource: Addr(a.LocalAddr()), ControlDestination: Addr(a.RemoteAddr())})
	if src != "192.0.2.1:45001" || kind != "system_proxy" {
		t.Fatal(src, kind)
	}
}

func TestStage4TupleBudgetAndSaturation(t *testing.T) {
	block := make(chan struct{})
	done := make(chan struct{}, 4)
	var active, max atomic.Int32
	lookup := func(context.Context, Query) Identity {
		n := active.Add(1)
		for old := max.Load(); n > old; old = max.Load() {
			if max.CompareAndSwap(old, n) {
				break
			}
		}
		<-block
		active.Add(-1)
		done <- struct{}{}
		return Identity{Status: "known", PID: 44, Stamp: 55}
	}
	for i := 0; i < 8; i++ {
		start := time.Now()
		id := budgetTuple(context.Background(), Query{}, lookup)
		if id.Status != "unknown" || id.Cause != "process:unknown" || id.PID != 0 || time.Since(start) > 100*time.Millisecond {
			t.Fatal("lookup blocked forwarding or trusted late proof")
		}
	}
	if max.Load() != 4 {
		t.Fatal("native concurrency", max.Load())
	}
	close(block)
	for i := 0; i < 4; i++ {
		<-done
	}
	// Worker slot is released by worker, not by forwarding timeout.
	end := time.Now().Add(time.Second)
	for len(tupleSlots) > 0 && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	if len(tupleSlots) != 0 {
		t.Fatal("slots leaked")
	}
	fresh := budgetTuple(context.Background(), Query{}, func(context.Context, Query) Identity {
		return Identity{Status: "known", Name: "fresh.exe", Path: `C:\Apps\fresh.exe`, PID: 45, Stamp: 56}
	})
	if fresh.Status != "known" || fresh.PID != 45 {
		t.Fatal("late result or global positive reused", fresh)
	}
}
func TestStage4OwnerUnknownAmbiguousAndPIDReuse(t *testing.T) {
	q := Query{Network: "udp", Source: netip.MustParseAddrPort("10.0.0.2:6000")}
	for _, netw := range []string{"udp", "tcp"} {
		q.Network = netw
		q.Destination = netip.MustParseAddrPort("203.0.113.1:443")
		row := Row{Source: q.Source, Destination: q.Destination, PID: 9}
		calls := 0
		r := resolveCurrent(q, func(Query) ([]Row, string) {
			calls++
			if calls == 2 {
				row.PID = 10
			}
			return []Row{row}, "known"
		}, func(uint32) (Identity, func() bool, func()) {
			return Identity{Status: "known", PID: 9, Stamp: 1}, func() bool { return true }, func() {}
		})
		if r.Status != "changed" {
			t.Fatal("PID owner changed accepted", r)
		}
		r = resolveCurrent(q, func(Query) ([]Row, string) { return []Row{row, row}, "known" }, nil)
		if r.Status != "ambiguous" {
			t.Fatal(r)
		}
		r = resolveCurrent(q, func(Query) ([]Row, string) { return nil, "known" }, nil)
		if r.Status == "known" {
			t.Fatal("empty table accepted")
		}
		r = resolveCurrent(q, func(Query) ([]Row, string) { return []Row{row}, "known" }, func(uint32) (Identity, func() bool, func()) {
			return Identity{Status: "known", PID: 10, Stamp: 1}, func() bool { return false }, func() {}
		})
		if r.Status != "changed" {
			t.Fatal("creation/handle stale accepted")
		}
	}
}

func TestStage4UDPLocalEvidenceNotRemote(t *testing.T) {
	for _, f := range []struct{ source, wildcard, other string }{
		{"192.0.2.1:6000", "0.0.0.0:6000", "192.0.2.2:6000"},
		{"[2001:db8::1]:6000", "[::]:6000", "[2001:db8::2]:6000"},
	} {
		q := Query{Network: "udp", Source: ap(f.source), Destination: ap("203.0.113.1:443")}
		exact := Row{Source: q.Source, PID: 9}
		wild := Row{Source: ap(f.wildcard), PID: 10}
		for _, tc := range []struct {
			name   string
			rows   []Row
			status string
		}{
			{"unique local", []Row{exact}, "known"},
			{"wildcard only", []Row{wild}, "unknown"},
			{"exact plus wildcard", []Row{exact, wild}, "ambiguous"},
			{"same PID reused bind", []Row{exact, exact}, "ambiguous"},
			{"different PID reused bind", []Row{exact, {Source: q.Source, PID: 11}}, "ambiguous"},
			{"other interface", []Row{{Source: ap(f.other), PID: 11}}, "closed"},
		} {
			t.Run(f.source+"/"+tc.name, func(t *testing.T) {
				pid, status := unique(tc.rows, q)
				if status != tc.status || status != "known" && pid != 0 {
					t.Fatal(pid, status)
				}
				q.Destination = ap("198.51.100.2:53")
				if p, s := unique(tc.rows, q); p != pid || s != status {
					t.Fatal("UDP table fabricated remote evidence", p, s)
				}
			})
		}
	}
	q := Query{Network: "tcp", Source: ap("192.0.2.1:6000"), Destination: ap("203.0.113.1:443")}
	if _, status := unique([]Row{{Source: q.Source, Destination: ap("203.0.113.2:443"), PID: 9}}, q); status != "closed" {
		t.Fatal("TCP remote endpoint ignored", status)
	}
}

func TestStage4SecondSnapshotAndProofFailuresRevoke(t *testing.T) {
	q := Query{Network: "udp", Source: ap("192.0.2.1:6000")}
	row := Row{Source: q.Source, PID: 9}
	for _, tc := range []struct {
		name              string
		rows              []Row
		tableStatus, want string
	}{
		{"new ambiguity", []Row{row, row}, "known", "ambiguous"},
		{"wildcard replaced exact", []Row{{Source: ap("0.0.0.0:6000"), PID: 9}}, "known", "unknown"},
		{"new owner", []Row{{Source: q.Source, PID: 10}}, "known", "changed"},
		{"closed", nil, "known", "changed"},
		{"permission lost", nil, "denied", "denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, closes := 0, 0
			id := resolveCurrent(q, func(Query) ([]Row, string) {
				calls++
				if calls == 1 {
					return []Row{row}, "known"
				}
				return tc.rows, tc.tableStatus
			}, func(uint32) (Identity, func() bool, func()) {
				return Identity{Status: "known", Name: "app.exe", Path: `C:\Apps\app.exe`, PID: 9, Stamp: 100}, func() bool { return true }, func() { closes++ }
			})
			if id.Status != tc.want || id.Cause != "process:"+tc.want || id.Name != "" || id.PID != 0 || id.Stamp != 0 || closes != 1 {
				t.Fatal(id, closes)
			}
		})
	}
	for _, proof := range []Identity{{Status: "known", PID: 10, Stamp: 100}, {Status: "known", PID: 9}} {
		id := resolveCurrent(q, func(Query) ([]Row, string) { return []Row{row}, "known" }, func(uint32) (Identity, func() bool, func()) { return proof, func() bool { return true }, func() {} })
		if id.Status != "changed" || id.PID != 0 {
			t.Fatal("invalid PID/creation proof accepted", id)
		}
	}
}

func TestStage4CreationAndHandleProof(t *testing.T) {
	if !processCreatedBefore(100, 101) || !processCreatedBefore(100, 100) || processCreatedBefore(102, 101) || processCreatedBefore(0, 101) {
		t.Fatal("snapshot-to-open recycled PID accepted")
	}
	if !processProofCurrent(100, 100, true) || processProofCurrent(100, 101, true) || processProofCurrent(0, 0, true) || processProofCurrent(100, 100, false) {
		t.Fatal("creation change or dead process accepted")
	}
}

func TestStage4BudgetCancellationAndFailureEvidence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	id := budgetTuple(ctx, Query{}, func(context.Context, Query) Identity {
		t.Error("canceled query entered native lookup")
		return Identity{}
	})
	if id.Status != "unknown" || id.Cause != "process:unknown" {
		t.Fatal(id)
	}
	for _, status := range []string{"ambiguous", "unknown", "denied"} {
		id = budgetTuple(context.Background(), Query{}, func(context.Context, Query) Identity {
			return Identity{Status: status, Cause: "process:" + status, Win32: 5, Name: "stale.exe", Path: `C:\stale.exe`, PID: 9, Stamp: 100}
		})
		if id.Status != status || id.Cause != "process:"+status || id.Win32 != 5 || id.Name != "" || id.Path != "" || id.PID != 0 || id.Stamp != 0 {
			t.Fatal(id)
		}
	}
}
