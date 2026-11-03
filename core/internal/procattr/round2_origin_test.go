package procattr

import (
	"context"
	"net"
	"testing"
)

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
