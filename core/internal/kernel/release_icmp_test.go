package kernel

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/tunstack"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func releaseICMPRequest() tunstack.ICMPEchoRequest {
	return tunstack.ICMPEchoRequest{Source: netip.MustParseAddr("10.50.0.2"), Destination: netip.MustParseAddr("203.0.113.50"), Ident: 17, Sequence: 29, TTL: 43, TOS: 8, DF: true, Payload: []byte("original Echo payload"), Epoch: 4}
}
func TestReleaseICMPDirectAndReject(t *testing.T) {
	for _, mode := range []string{"direct-ok", "direct-fail", "reject"} {
		t.Run(mode, func(t *testing.T) {
			q := releaseICMPRequest()
			var calls atomic.Int32
			s := c50Server(t, nil, func(c *Config) {
				c.Routing = &RoutingOptions{Final: "direct"}
				if mode == "reject" {
					c.Routing.Final = "reject"
				}
				c.SetClientEgress(&ClientEgress{PingPhysical: func(_ context.Context, d netip.Addr, ttl, tos uint8, df bool, p []byte) ([]byte, uint8, error) {
					calls.Add(1)
					if d != q.Destination || ttl != 43 || tos != 8 || !df || !bytes.Equal(p, q.Payload) {
						t.Error("physical arguments not preserved")
					}
					if mode == "direct-fail" {
						return nil, 0, errors.New("injected physical failure")
					}
					return []byte("physical response"), 31, nil
				}})
			})
			rep, send := c50Ingress(t, s).HandleICMP(context.Background(), q)
			want := int32(1)
			if mode == "reject" {
				want = 0
			}
			if calls.Load() != want {
				t.Fatal("wrong physical call count", calls.Load())
			}
			if mode == "direct-ok" {
				if !send || rep.TTL != 31 || string(rep.Payload) != "physical response" {
					t.Fatal("physical result not preserved", rep, send)
				}
			} else if send {
				t.Fatal("failed/rejected ICMP generated success")
			}
		})
	}
}

type releaseProbeOutbound struct {
	dial func(context.Context, outbound.Addr) (net.Conn, error)
}

func (o *releaseProbeOutbound) DialTCP(c context.Context, a outbound.Addr) (net.Conn, error) {
	return o.dial(c, a)
}
func (*releaseProbeOutbound) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, outbound.ErrUDPUnsupported
}
func (*releaseProbeOutbound) UDP() bool    { return false }
func (*releaseProbeOutbound) Name() string { return "ReleaseProbe" }
func (*releaseProbeOutbound) Type() string { return "test-memory" }
func (*releaseProbeOutbound) Close() error { return nil }
func TestReleaseICMPProxyProbeAndCancel(t *testing.T) {
	for _, mode := range []string{"head204", "head500", "dial-fail", "cancel", "head405-get"} {
		t.Run(mode, func(t *testing.T) {
			var physical atomic.Int32
			s := c50Server(t, nil, func(c *Config) {
				c.Outbounds = []OutboundConfig{{Name: "ReleaseProbe", Type: "socks5", Server: "127.0.0.1", Port: 1}}
				c.Routing = &RoutingOptions{Final: "ReleaseProbe"}
				c.SetClientEgress(&ClientEgress{ProbeURL: "http://probe.invalid:8080/check", PingPhysical: func(context.Context, netip.Addr, uint8, uint8, bool, []byte) ([]byte, uint8, error) {
					physical.Add(1)
					return nil, 0, errors.New("unexpected physical call")
				}})
			})
			entered := make(chan struct{}, 2)
			observed := make(chan string, 4)
			problems := make(chan error, 4)
			var dials atomic.Int32
			fake := &releaseProbeOutbound{dial: func(ctx context.Context, a outbound.Addr) (net.Conn, error) {
				dials.Add(1)
				if a.Host != "probe.invalid" || a.Port != 8080 {
					problems <- fmt.Errorf("not probe target: %+v", a)
				}
				entered <- struct{}{}
				if mode == "dial-fail" {
					return nil, errors.New("injected dial failure")
				}
				if mode == "cancel" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				aSide, bSide := net.Pipe()
				go func() {
					defer bSide.Close()
					rd := bufio.NewReader(bSide)
					for i := 0; i < 2; i++ {
						req, e := http.ReadRequest(rd)
						if e != nil {
							if i == 0 {
								problems <- e
							}
							return
						}
						observed <- req.Method + " " + req.URL.RequestURI() + " " + req.Host
						req.Body.Close()
						status := 204
						if mode == "head500" {
							status = 500
						}
						if mode == "head405-get" && i == 0 {
							status = 405
						}
						_, e = fmt.Fprintf(bSide, "HTTP/1.1 %d Fixture\r\nContent-Length: 0\r\n\r\n", status)
						if e != nil {
							return
						}
						if mode != "head405-get" || i == 1 {
							return
						}
					}
				}()
				return aSide, nil
			}}
			s.rt.nodes["ReleaseProbe"] = fake
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			q := releaseICMPRequest()
			type answer struct {
				rep  tunstack.ICMPEchoReply
				send bool
			}
			done := make(chan answer, 1)
			ingress := c50Ingress(t, s)
			go func() { rep, send := ingress.HandleICMP(parent, q); done <- answer{rep, send} }()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("probe never entered fake outbound")
			}
			if mode == "cancel" {
				cancel()
			}
			var got answer
			select {
			case got = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("probe failed to settle/cancel")
			}
			success := mode == "head204" || mode == "head405-get"
			if got.send != success {
				t.Fatalf("mode %s: send=%t", mode, got.send)
			}
			if success && (!bytes.Equal(got.rep.Payload, q.Payload) || got.rep.TTL != 56) {
				t.Fatal("synthetic Echo identity/TTL not preserved", got.rep)
			}
			if physical.Load() != 0 || dials.Load() != 1 {
				t.Fatal("wrong route path", physical.Load(), dials.Load())
			}
			if mode == "head204" || mode == "head500" || mode == "head405-get" {
				want := []string{"HEAD /check probe.invalid:8080"}
				if mode == "head405-get" {
					want = append(want, "GET /check probe.invalid:8080")
				}
				var seen []string
				for len(observed) > 0 {
					seen = append(seen, <-observed)
				}
				if !reflect.DeepEqual(seen, want) {
					t.Fatal("probe method/target", seen, want)
				}
			}
			if len(problems) > 0 {
				t.Fatal(<-problems)
			}
		})
	}
}
