package procattr

import (
	"context"
	"testing"
)

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
