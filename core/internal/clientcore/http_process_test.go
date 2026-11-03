package clientcore

import (
	"context"
	"net"
	"net/http"
	"testing"
)

func TestHTTPProcessPoolsArePerAcceptedConnection(t *testing.T) {
	b, err := newHTTPBridge(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	a, peerA := net.Pipe()
	defer a.Close()
	defer peerA.Close()
	c, peerC := net.Pipe()
	defer c.Close()
	defer peerC.Close()
	ctxA := b.server.ConnContext(context.Background(), a)
	ctxC := b.server.ConnContext(context.Background(), c)
	one := ctxA.Value(httpOriginKey{}).(*httpOrigin)
	two := ctxC.Value(httpOriginKey{}).(*httpOrigin)
	if one == two || one.origin == two.origin || one.transport == two.transport || one.transport == b.transport {
		t.Fatal("cross-client transport/identity reuse")
	}
	if len(b.transports) != 2 {
		t.Fatal(len(b.transports))
	}
	b.server.ConnState(a, http.StateClosed)
	if len(b.transports) != 1 {
		t.Fatal("closed pool retained")
	}
	b.server.ConnState(c, http.StateHijacked)
	if len(b.transports) != 0 {
		t.Fatal("hijacked pool retained")
	}
}
