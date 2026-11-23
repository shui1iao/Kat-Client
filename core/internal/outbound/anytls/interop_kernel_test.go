package anytls

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// Kat-Client contains no inbound AnyTLS server. Run interop against a separately
// built Kat-Server: KAT_INTEROP_SERVER=/absolute/path/to/kat go test ./internal/outbound/anytls
// Only test-owned children, temporary files and loopback listeners are used.
const testServerEnv = "KAT_INTEROP_SERVER"

type katServer struct {
	addr        outbound.Addr
	bin, config string
	cmd         *exec.Cmd
	exited      chan struct{}
	log         bytes.Buffer // read only after Wait
}

func katFixture(t *testing.T, options ...map[string]any) (testCert, *katServer) {
	t.Helper()
	bin := os.Getenv(testServerEnv)
	if bin == "" {
		t.Skip("set " + testServerEnv + " to a Kat-Server binary for process interop")
	}
	cert := newTestCert(t)
	addr := outbound.Addr{Host: "127.0.0.1", Port: uint16(freePort(t))}
	dir := t.TempDir()
	srv := &katServer{addr: addr, bin: bin, config: filepath.Join(dir, "config.json")}
	opts := map[string]any{"password": testPassword}
	for _, fields := range options {
		for k, v := range fields {
			opts[k] = v
		}
	}
	cfg := map[string]any{
		"inbounds": []any{map[string]any{"protocol": "anytls", "listen": addr.String(), "tls": map[string]string{"cert": cert.certFile, "key": cert.keyFile}, "anytls": opts}},
		"security": map[string]bool{"allow_loopback": true}, "api": map[string]bool{"enabled": false}, "stats": map[string]bool{"persist": false},
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(srv.config, b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.stop)
	srv.start(t)
	return cert, srv
}
func (s *katServer) start(t *testing.T) {
	t.Helper()
	cmd := exec.Command(s.bin, "run", s.config)
	cmd.Dir = filepath.Dir(s.config)
	s.log.Reset()
	cmd.Stderr = &s.log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s.cmd = cmd
	done := make(chan struct{})
	s.exited = done
	go func() { _ = cmd.Wait(); close(done) }()
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
		select {
		case <-done:
			t.Fatalf("Kat-Server exited during startup: %s", s.log.String())
		default:
		}
		if c, e := net.DialTimeout("tcp", s.addr.String(), 100*time.Millisecond); e == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Kat-Server did not start listening")
}
func (s *katServer) stop() {
	if s.cmd != nil {
		_ = s.cmd.Process.Kill()
		<-s.exited
		s.cmd = nil
	}
}

func TestKatKernelInterop(t *testing.T) {
	cert, srv := katFixture(t)
	echo := tcpEchoServer(t)
	under := &countingDialer{}
	ob := newTestOutbound(t, baseOptions(srv.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert.pin}), under)
	defer ob.Close()

	c, e := ob.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	if e = echoRoundTrip(c, []byte("hello kat kernel")); e != nil {
		t.Fatal(e)
	}
	c.Close()
	waitIdle(t, ob, 1)
	concurrentEcho(t, ob, echo, 8, 200<<10) // 8 distinct sessions, one reused
	if n, d := ob.sessionsCreated.Load(), under.n.Load(); n != 8 || d != 8 {
		t.Fatalf("sessions=%d under dials=%d, want 8/8", n, d)
	}
	waitIdle(t, ob, 4)
	c, e = ob.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	if e = echoRoundTrip(c, []byte("reuse")); e != nil {
		t.Fatal(e)
	}
	c.Close()
	if n, d := ob.sessionsCreated.Load(), under.n.Load(); n != 8 || d != 8 {
		t.Fatalf("reuse: sessions=%d under dials=%d, want 8/8", n, d)
	}
	t.Logf("TCP via Kat server: echo + 8 concurrent on 8 sessions + idle reuse (under dials 8)")

	pc, e := ob.ListenPacket(ctxTimeout(t, 5*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	u1, u2 := udpEchoServer(t, "k1:"), udpEchoServer(t, "k2:")
	udpRoundTrip(t, pc, u1, []byte("kernel uot 1"), "k1:")
	udpRoundTrip(t, pc, u2, []byte("kernel uot 2"), "k2:")
	udpRoundTrip(t, pc, u1, pattern(7, 1400), "k1:")
	if d := under.n.Load(); d != 8 {
		t.Fatalf("UoT should take an idle session; under dials=%d", d)
	}
	t.Logf("UoT v2 via Kat server: replies from %v and %v verified", u1, u2)

	// Server shutdown with live streams: they error; a restarted server gets a new session.
	c, e = ob.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal(e)
	}
	srv.stop()
	errc := make(chan error, 2)
	go func() { _, e := c.Read(make([]byte, 8)); errc <- e }()
	go func() { _, _, e := pc.ReadFrom(make([]byte, 8)); errc <- e }()
	for i := 0; i < 2; i++ {
		select {
		case e := <-errc:
			if e == nil {
				t.Fatal("read succeeded after server shutdown")
			}
			t.Logf("live stream after kernel shutdown: %v", e)
		case <-time.After(5 * time.Second):
			t.Fatal("stream hangs after server shutdown")
		}
	}
	c.Close()
	pc.Close()
	before := ob.sessionsCreated.Load()
	srv.start(t)
	c, e = ob.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if e != nil {
		t.Fatal("dial after restart:", e)
	}
	if e = echoRoundTrip(c, []byte("after restart")); e != nil {
		t.Fatal(e)
	}
	c.Close()
	if n := ob.sessionsCreated.Load(); n != before+1 {
		t.Fatalf("sessions=%d, want %d (one new session after restart)", n, before+1)
	}
}
