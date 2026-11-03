package kernel

import (
	"context"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestColdDependencyFirstRequest(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	blackhole, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer blackhole.Close()
	var mu sync.Mutex
	var sockets []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := blackhole.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			sockets = append(sockets, c)
			mu.Unlock()
			go io.Copy(io.Discard, c)
		}
	}()
	defer func() {
		blackhole.Close()
		<-done
		mu.Lock()
		for _, c := range sockets {
			c.Close()
		}
		mu.Unlock()
	}()
	good := socksCfg("127.0.0.1:0")
	good.Inbounds[0] = Inbound{Protocol: "shadowsocks", Listen: "127.0.0.1:0", SS: &SSOptions{Method: "aes-128-gcm", Password: "synthetic"}}
	good.DNS = &DNSOptions{Server: "system"}
	good.Log = &LogOptions{Level: "error"}
	up := groupsStart(t, good)
	tail := socksCfg("127.0.0.1:0")
	tail.DNS = &DNSOptions{Server: "system"}
	tail.Log = &LogOptions{Level: "error"}
	next := groupsStart(t, tail)
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Log = &LogOptions{Level: "error"}
	c.Outbounds = []OutboundConfig{
		{Name: "cold-first", Type: "shadowsocks", Server: "127.0.0.1", Port: uint16(blackhole.Addr().(*net.TCPAddr).Port), Method: "aes-128-gcm", Password: "synthetic"},
		{Name: "healthy-last", Type: "shadowsocks", Server: "127.0.0.1", Port: uint16(up.Addresses()[0].(*net.TCPAddr).Port), Method: "aes-128-gcm", Password: "synthetic"},
		{Name: "tail", Type: "socks5", Server: "127.0.0.1", Port: uint16(next.Addresses()[0].(*net.TCPAddr).Port), Via: "dep"}}
	c.Groups = []GroupConfig{{Name: "dep", Type: "url-test", Members: []string{"cold-first", "healthy-last"}, Probe: &group.ProbeOptions{URL: target.URL, Timeout: outbound.Duration(200 * time.Millisecond)}}}
	s := groupsStart(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, e := s.ProbeNode(ctx, "tail", target.URL)
	if e != nil || r.ProbeMS == nil {
		t.Fatal("first request used silent unprobed member although initial round has a healthy last member")
	}
}
