package ss_test

import (
	"context"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/anytls"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/outbound/internal/proxytest"
	"github.com/shui1iao/Kat/internal/outbound/socks5"
	"github.com/shui1iao/Kat/internal/outbound/ss"
	"github.com/shui1iao/Kat/internal/outbound/trojan"
	"testing"
)

func TestObfsRejectedByOtherProtocols(t *testing.T) {
	for _, typ := range []string{"socks5", "trojan", "anytls"} {
		o := outbound.Options{Name: "test", Type: typ, Server: "127.0.0.1", Port: 1, Password: "fixture", Obfs: &outbound.SSObfsOptions{Mode: "http", Host: "example.com"}}
		if typ != "socks5" {
			o.TLS = &outbound.TLSOptions{}
		}
		var e error
		switch typ {
		case "socks5":
			e = socks5.Validate(o)
		case "trojan":
			e = trojan.Validate(o)
		case "anytls":
			e = anytls.Validate(o)
		}
		if e == nil {
			t.Fatal("inapplicable obfs accepted")
		}
	}
}
func TestObfsNativeUDPCapability(t *testing.T) {
	o := opts("aes-128-gcm", 1, false)
	o.Obfs = &outbound.SSObfsOptions{Mode: "http", Host: "example.com"}
	under := direct.New(direct.Options{})
	noUDP := proxytest.TCPOnly{Under: under}
	ob, e := ss.New(o, noUDP)
	if e != nil || ob.UDP() {
		t.Fatal("under UDP capability lost")
	}
	if _, e = ob.ListenPacket(context.Background()); e != outbound.ErrUDPUnsupported {
		t.Fatal("unsupported UDP bypass")
	}
	f := false
	o.UDP = &f
	ob, e = ss.New(o, under)
	if e != nil || ob.UDP() {
		t.Fatal("explicit UDP false")
	}
	if _, e = ob.ListenPacket(context.Background()); e != outbound.ErrUDPUnsupported {
		t.Fatal("disabled UDP bypass")
	}
}
