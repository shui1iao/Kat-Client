package kernel

import (
	"bufio"
	"bytes"
	"context"

	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"

	"strings"
	"testing"
	"time"
)

// socksConnect opens a SOCKS5 CONNECT through s and returns the reply code.

func TestBlockedDestinationTable(t *testing.T) {
	def := Config{}
	allow := Config{Security: &SecurityOptions{AllowLoopback: true}}
	priv := Config{Security: &SecurityOptions{BlockPrivate: true}}
	for _, tc := range []struct {
		ip                  string
		def, allowed, block bool
	}{
		{"127.0.0.1", true, false, true},
		{"127.1.2.3", true, false, true},
		{"::1", true, false, true},
		{"::ffff:127.0.0.1", true, false, true},
		{"0.0.0.0", true, false, true},
		{"0.1.2.3", true, false, true},
		{"::", true, false, true},
		{"::ffff:0.0.0.0", true, false, true},
		{"10.1.2.3", false, false, true},
		{"172.16.0.1", false, false, true},
		{"192.168.1.1", false, false, true},
		{"100.64.0.1", false, false, true},
		{"169.254.1.1", false, false, true},
		{"fd00::1", false, false, true},
		{"fe80::1", false, false, true},
		{"::ffff:192.168.1.1", false, false, true},
		{"1.1.1.1", false, false, false},
		{"2606:4700::1111", false, false, false},
	} {
		ip := netip.MustParseAddr(tc.ip)
		if def.blockedDestination(ip) != tc.def || allow.blockedDestination(ip) != tc.allowed || priv.blockedDestination(ip) != tc.block {
			t.Errorf("%s: default=%v allow=%v private=%v", tc.ip, def.blockedDestination(ip), allow.blockedDestination(ip), priv.blockedDestination(ip))
		}
	}
}

func TestLogLevels(t *testing.T) {
	var buf bytes.Buffer
	l, _ := newLogger(&LogOptions{Level: "warn"})
	l.write = func(p []byte) error { buf.Write(p); return nil }
	l.emit(levelInfo, []byte("kat event=info_line\n"))
	l.emit(levelWarn, []byte("kat event=warn_line\n"))
	l.setLevel(levelDebug)
	l.emit(levelDebug, []byte("kat event=debug_line\n"))
	if got := buf.String(); got != "kat event=warn_line\nkat event=debug_line\n" {
		t.Fatalf("%q", got)
	}
	for _, bad := range []string{"trace", "INFO2"} {
		if _, ok := parseLevel(bad); ok {
			t.Fatal(bad)
		}
	}
	if (&Config{Log: &LogOptions{Level: "loud"}}).validateRuntime() == nil || (&Config{Log: &LogOptions{Format: "xml"}}).validateRuntime() == nil || (&Config{Log: &LogOptions{File: "rel.log"}}).validateRuntime() == nil {
		t.Fatal("bad log options accepted")
	}
}

func TestDefaultLogUnchanged(t *testing.T) {
	// No "log" block: lines reach the sink byte-for-byte (0.6.3 format).
	l, e := newLogger(nil)
	if e != nil || l.json || l.file != nil || l.access.Load() || l.getLevel() != levelInfo {
		t.Fatal("default logger changed")
	}
	var buf bytes.Buffer
	l.write = func(p []byte) error { buf.Write(p); return nil }
	l.emit(levelWarn, []byte("kat event=failure stage=dial reason=connect_failed protocol=outbound inbound=-1 suppressed=0\n"))
	if buf.String() != "kat event=failure stage=dial reason=connect_failed protocol=outbound inbound=-1 suppressed=0\n" {
		t.Fatalf("%q", buf.String())
	}
}

func TestRotatingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.log")
	r, e := openRotatingFile(path, 100, 2)
	if e != nil {
		t.Fatal(e)
	}
	line := bytes.Repeat([]byte("a"), 39)
	line = append(line, '\n')
	for i := 0; i < 10; i++ {
		if e := r.Write(line); e != nil {
			t.Fatal(e)
		}
	}
	r.Close()
	for _, p := range []string{path, path + ".1", path + ".2"} {
		st, e := os.Stat(p)
		if e != nil || st.Size() > 100 || st.Mode().Perm() != 0o600 {
			t.Fatal(p, e)
		}
	}
	if _, e := os.Stat(path + ".3"); e == nil {
		t.Fatal("more backups than configured")
	}
}

func TestJSONLine(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	got := string(jsonLine(now, levelWarn, []byte("kat event=failure stage=dial inbound=-1 suppressed=0 count=12\n")))
	want := `{"time":"2026-01-02T03:04:05Z","level":"warn","event":"failure","stage":"dial","inbound":"-1","suppressed":0,"count":12}` + "\n"
	if got != want {
		t.Fatalf("%s", got)
	}
	got = string(jsonLine(now, levelInfo, []byte("listening 127.0.0.1:1\n")))
	if got != `{"time":"2026-01-02T03:04:05Z","level":"info","msg":"listening 127.0.0.1:1"}`+"\n" {
		t.Fatal(got)
	}
}

func TestTruncateSource(t *testing.T) {
	for in, want := range map[string]string{"203.0.113.77": "203.0.113.0/24", "::ffff:203.0.113.77": "203.0.113.0/24", "2001:db8:1234:5678::1": "2001:db8:1234::/48", "fe80::1%eth0": "fe80::/48"} {
		if got := truncateSource(netip.MustParseAddr(in)); got != want {
			t.Errorf("%s -> %s", in, got)
		}
	}
	if truncateSource(netip.Addr{}) != "-" {
		t.Fatal("invalid")
	}
}

// apiClient talks HTTP over the Unix socket.
func unixClient(path string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}, Timeout: 5 * time.Second}
}

func freeTCPPort(t *testing.T) int {
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestAccessLogLineScanner(t *testing.T) {
	// Every access line is one line even with hostile target names.
	var buf bytes.Buffer
	lg := &logger{write: func(p []byte) error { buf.Write(p); return nil }}
	lg.access.Store(true)
	s := &Server{core: &core{log: lg}}
	s.log.level.Store(int32(levelInfo))
	f := &flow{s: s, id: 7, network: "tcp", start: time.Now(), target: "a b\nkat event=fake:80", src: netip.MustParseAddr("2001:db8::1")}
	s.accessLine(f)
	sc := bufio.NewScanner(&buf)
	n := 0
	for sc.Scan() {
		n++
		if !strings.Contains(sc.Text(), "src=2001:db8::/48") {
			t.Fatal(sc.Text())
		}
	}
	if n != 1 {
		t.Fatal("line split", buf.String())
	}
	_ = io.Discard
}

// Groups and protocol outbounds: the guard applies to the final direct dial
// of client traffic only; Kat's own dial to an upstream on loopback is not
// client traffic. Chains and group counters follow the chosen members.
