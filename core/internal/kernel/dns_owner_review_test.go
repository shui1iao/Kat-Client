package kernel

import (
	"context"
	"golang.org/x/net/dns/dnsmessage"
	"testing"
)

func TestReviewDNSOwnerAndLANBinding(t *testing.T) {
	names := []string{".", "_ldap._tcp.office.lan", "printer.local"}
	types := []dnsmessage.Type{dnsmessage.TypeNS, dnsmessage.TypeSRV, dnsmessage.TypeHTTPS}
	calls := 0
	s := startTest(t, Inbound{Protocol: "socks5", Name: "kat-client"}, func(c *Config) {
		c.SetClientDNSConfig(nil, nil, "rule", "direct")
		c.SetClientEgress(&ClientEgress{Active: func() bool { return true }, SystemQuery: func(_ context.Context, w []byte) ([]byte, error) {
			m, e := dnsRequest(w)
			if e != nil {
				return nil, e
			}
			calls++
			r := dnsGatewayReply(m, dnsmessage.RCodeSuccess)
			r.AuthenticData = true
			if m.Questions[0].Type == dnsmessage.TypeHTTPS {
				r.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.MustNewName("."), Params: []dnsmessage.SVCParam{{Key: 1, Value: []byte{2, 'h', '2'}}}}}}}
			}
			return r.Pack()
		}})
	})
	for i, name := range names {
		wire := buildDNSQuery(t, uint16(i), name, types[i])
		r, e := s.answerDNS(context.Background(), wire, false)
		if e != nil {
			t.Fatal(name, e)
		}
		m := unpackDNSReply(t, r)
		if !m.AuthenticData || m.RCode != dnsmessage.RCodeSuccess || m.Questions[0].Type != types[i] {
			t.Fatal(name, m)
		}
		if i == 2 {
			if len(m.Answers) != 1 {
				t.Fatalf("lost local binding: %v", m)
			}
			b, ok := m.Answers[0].Body.(*dnsmessage.HTTPSResource)
			if !ok || len(b.Params) != 1 || b.Params[0].Key != 1 {
				t.Fatal("lost LAN ALPN", b)
			}
		}
	}
	if calls != 3 {
		t.Fatalf("upstream calls=%d", calls)
	}
}
