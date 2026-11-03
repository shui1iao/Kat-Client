package route

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUIResourceRefreshReusesSafeDownloader(t *testing.T) {
	org := newOrigin(t, "+.remote.example\n")
	path := filepath.Join(t.TempDir(), "r.txt")
	dr := &dialRecorder{}
	ev := &eventLog{}
	e := remoteEngine(t, Options{RuleSets: []RuleSetOptions{{Name: "r", Format: "domain", Path: path, URL: org.srv.URL + "/private?token=SECRET", Via: "chain-a"}}}, org, dr, ev, time.Hour, time.Minute)
	if r := e.Resources(); len(r) != 1 || r[0].State != "pending" || r[0].UpdatedAt != nil {
		t.Fatal(r)
	}
	if err := e.RefreshResource(context.Background(), "rule_set", "r"); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, path)
	r := e.Resources()
	if len(r) != 1 || r[0].State != "ok" || r[0].Entries == nil || *r[0].Entries != 1 || r[0].SizeBytes == nil || r[0].UpdatedAt == nil || dr.first() != "chain-a" {
		t.Fatal(r)
	}
	r[0].State = "modified"
	*r[0].Entries = 99
	if e.Resources()[0].State != "ok" || *e.Resources()[0].Entries != 1 {
		t.Fatal("alias")
	}
	for _, mode := range []string{"500", "html"} {
		org.set(mode, "")
		err := e.RefreshResource(context.Background(), "rule_set", "r")
		if !errors.Is(err, ErrResourceRefresh) || readFile(t, path) != before || e.Resources()[0].State != "error" {
			t.Fatal(mode, err, e.Resources())
		}
		noTmp(t, path)
	}
	// Untrusted TLS certificate must still fail; no alternate downloader is used.
	e.rootCAs = nil
	org.set("", "+.changed.example\n")
	old := readFile(t, path)
	if err := e.RefreshResource(context.Background(), "rule_set", "r"); !errors.Is(err, ErrResourceRefresh) || readFile(t, path) != old || e.Resources()[0].Code != "tls" {
		t.Fatal(err, e.Resources())
	}
	b, _ := json.Marshal(e.Resources())
	for _, secret := range []string{"SECRET", "token", "private", org.srv.URL, path} {
		if strings.Contains(string(b), secret) {
			t.Fatal("metadata leak", string(b))
		}
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.RefreshResource(c, "rule_set", "r"); !errors.Is(err, ErrResourceRefresh) || readFile(t, path) != old {
		t.Fatal("cancellation wrote", err)
	}
	if err := e.RefreshResource(context.Background(), "rule_set", "unknown"); !errors.Is(err, ErrResourceUnsupported) {
		t.Fatal(err)
	}
}
func TestUIResourceLocalStatesAndDatabases(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.txt")
	if err := os.WriteFile(p, []byte("+.local.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(Options{RuleSets: []RuleSetOptions{{Name: "r", Format: "domain", Path: p}}, GeoIP: &GeoIPOptions{Path: filepath.Join(dir, "missing.mmdb")}, ASN: &GeoIPOptions{Path: filepath.Join(dir, "bad.mmdb")}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	r := e.Resources()
	if len(r) != 3 || r[0].State != "ok" || r[1].Name != "geoip" || r[1].State != "missing" || r[2].Name != "asn" || r[2].State != "missing" {
		t.Fatal(r)
	}
	for _, v := range r {
		if err := e.RefreshResource(context.Background(), v.Kind, v.Name); !errors.Is(err, ErrResourceUnsupported) {
			t.Fatal(v, err)
		}
	}
}

func TestUIResourceDatabaseRefreshAndKeepOld(t *testing.T) {
	for _, kind := range []string{"geoip", "asn"} {
		t.Run(kind, func(t *testing.T) {
			body := testMMDB(t)
			if kind == "asn" {
				body = testASNDB(t)
			}
			org := newOrigin(t, string(body))
			p := filepath.Join(t.TempDir(), kind+".mmdb")
			o := Options{}
			cfg := &GeoIPOptions{Path: p, URL: org.srv.URL + "/db?token=SECRET"}
			if kind == "geoip" {
				o.GeoIP = cfg
			} else {
				o.ASN = cfg
			}
			e := remoteEngine(t, o, org, &dialRecorder{}, &eventLog{}, time.Hour, time.Minute)
			if err := e.RefreshResource(context.Background(), kind, kind); err != nil {
				t.Fatal(err)
			}
			views := e.Resources()
			if len(views) != 1 || views[0].Name != kind || views[0].State != "ok" || views[0].Entries != nil || views[0].UpdatedAt == nil || views[0].SizeBytes == nil {
				t.Fatal(views)
			}
			old := readFile(t, p)
			org.set("html", "")
			if err := e.RefreshResource(context.Background(), kind, kind); !errors.Is(err, ErrResourceRefresh) || readFile(t, p) != old || e.Resources()[0].Code != "parse" {
				t.Fatal(err, e.Resources())
			}
			noTmp(t, p)
		})
	}
}

func TestUIResourceRefreshCancellationRetainsOld(t *testing.T) {
	org := newOrigin(t, "+.old.example\n")
	p := filepath.Join(t.TempDir(), "r.txt")
	e := remoteEngine(t, Options{RuleSets: []RuleSetOptions{{Name: "r", Format: "domain", Path: p, URL: org.srv.URL + "/r"}}}, org, &dialRecorder{}, &eventLog{}, time.Hour, time.Minute)
	if err := e.RefreshResource(context.Background(), "rule_set", "r"); err != nil {
		t.Fatal(err)
	}
	old := readFile(t, p)
	org.set("block", "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := e.RefreshResource(ctx, "rule_set", "r"); !errors.Is(err, ErrResourceRefresh) || readFile(t, p) != old {
		t.Fatal(err)
	}
	noTmp(t, p)
}

func TestUIResourceQueuedRefreshIsCancelable(t *testing.T) {
	org := newOrigin(t, "+.old.example\n")
	org.set("block", "")
	e := remoteEngine(t, Options{RuleSets: []RuleSetOptions{{Name: "r", Format: "domain", Path: filepath.Join(t.TempDir(), "r.txt"), URL: org.srv.URL + "/r"}}}, org, &dialRecorder{}, &eventLog{}, time.Hour, time.Minute)
	first, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.RefreshResource(first, "rule_set", "r") }()
	waitFor(t, time.Second, "blocked download", func() bool { return org.hits.Load() > 0 })
	second, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	start := time.Now()
	err := e.RefreshResource(second, "rule_set", "r")
	if !errors.Is(err, ErrResourceRefresh) || time.Since(start) > time.Second {
		t.Fatal("queued refresh ignored cancellation", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("first download did not cancel")
	}
}
