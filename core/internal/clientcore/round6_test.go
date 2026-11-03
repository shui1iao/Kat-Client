package clientcore

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/netip"
	"testing"
)

func TestR6ProxyHostnameBypassesFakeIPResolverOnce(t *testing.T) {
	for _, target := range []string{"sub.siaoz.com:443", "8.8.8.8:443", "raw.githubusercontent.com:443"} {
		t.Run(target, func(t *testing.T) {
			resolveCalls, dials, verified := 0, 0, 0
			var received string
			peerDone := make(chan struct{})
			c, e := dialBootstrapIO(context.Background(), target, &bootstrapProxy{Host: "127.0.0.1", Port: 7890}, nil, func(context.Context, string) ([]netip.Addr, error) {
				resolveCalls++
				return checkedImportAddresses([]netip.Addr{netip.MustParseAddr("198.18.0.42")}, nil)
			}, nil,
				func(context.Context, *net.Dialer, string) (net.Conn, error) {
					dials++
					a, b := net.Pipe()
					go func() {
						defer close(peerDone)
						defer b.Close()
						req, err := http.ReadRequest(bufio.NewReader(b))
						if err == nil {
							received = req.Host
							b.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
						}
					}()
					return a, nil
				}, func(net.Conn) error { verified++; return nil })
			if e != nil {
				t.Fatal(e)
			}
			c.Close()
			<-peerDone
			if received != target || resolveCalls != 0 || dials != 1 || verified != 1 {
				t.Fatal(received, resolveCalls, dials, verified)
			}
		})
	}
}
func TestR6ProxyPrivateLiteralAndLocalhostRefusedBeforeIO(t *testing.T) {
	for _, target := range []string{"10.1.2.3:443", "198.18.1.2:443", "[::1]:443", "127.0.0.1:443", "localhost:443", "foo.localhost:443", "LOCALHOST:443", "Foo.Localhost.:443", "localhost.:443"} {
		_, e := dialBootstrapIO(context.Background(), target, &bootstrapProxy{Host: "127.0.0.1", Port: 7890}, nil, func(context.Context, string) ([]netip.Addr, error) {
			t.Fatal("resolved forbidden target")
			return nil, nil
		}, nil, func(context.Context, *net.Dialer, string) (net.Conn, error) {
			t.Fatal("dialed forbidden target")
			return nil, nil
		}, func(net.Conn) error { t.Fatal("verified forbidden target"); return nil })
		assertDetail(t, e, "resolve", "address_refused")
	}
}
func TestR6DirectFakeIPClassificationStillRefusesAllReserved(t *testing.T) {
	for _, tc := range []struct{ ip, category string }{{"198.18.0.0", "fake_ip"}, {"198.18.1.42", "fake_ip"}, {"198.19.255.255", "fake_ip"}, {"10.0.0.1", "address_refused"}, {"127.0.0.1", "address_refused"}, {"198.20.0.1", ""}, {"142.91.102.205", ""}, {"192.0.2.1", "address_refused"}, {"::1", "address_refused"}} {
		ips, e := checkedImportAddresses([]netip.Addr{netip.MustParseAddr(tc.ip)}, nil)
		if tc.category == "" {
			if e != nil || len(ips) != 1 {
				t.Fatal(tc, e)
			}
			continue
		}
		assertDetail(t, e, "resolve", tc.category)
		if ips != nil {
			t.Fatal("refused destination leaked through")
		}
	}
	// The same exact resolver-result check propagates through HTTP error
	// wrapping and resource detail without becoming a generic connect failure.
	for _, tc := range []struct{ ip, category string }{{"198.18.22.1", "fake_ip"}, {"10.1.1.1", "address_refused"}} {
		_, e := fetchImportBounded(context.Background(), "https://sub.siaoz.com", nil, func(tr *http.Transport) http.RoundTripper {
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				_, err := checkedImportAddresses([]netip.Addr{netip.MustParseAddr(tc.ip)}, nil)
				return nil, err
			})
		}, 1024)
		assertDetail(t, e, "resolve", tc.category)
		d := resourceError(context.Background(), "subscription", 0, "download", "connect", "unknown", e)
		if d.Code != "subscription_fetch_failed" || d.Detail.Category != tc.category || d.Detail.Route != "direct" {
			t.Fatal(d)
		}
	}
}
