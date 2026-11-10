package kernel

import (
	"context"
	"github.com/shui1iao/Kat/internal/procattr"
	"net"
	"testing"
	"time"
)

func TestK3ProcessDetailsKnownUnknownAndPSL(t *testing.T) {
	old := lookupApplication
	defer func() { lookupApplication = old }()
	for _, status := range []string{"known", "ambiguous", "unknown", "denied"} {
		lookupApplication = func(context.Context, procattr.Query) procattr.Identity {
			return procattr.Identity{Name: "browser.exe", Path: `C:\Program Files\Browser\browser.exe`, Status: status}
		}
		ctx := withInboundMeta(context.Background(), &Inbound{Protocol: "socks5"}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7891}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 23456})
		s := &Server{core: &core{connectionSink: func(ConnectionEvent) {}, started: time.Now()}}
		f := &flow{s: s, network: "tcp"}
		addr := Address{Host: "api.example.co.uk", Port: 443}
		f.initDetails(ctx, addr)
		f.scheduleDetails(ctx, addr)
		waitFor(t, func() bool { return f.info(time.Now()).ProcessStatus == status })
		ci := f.info(time.Now())
		if ci.DomainSuffix != "example.co.uk" {
			t.Fatal(ci.DomainSuffix)
		}
		if status == "known" {
			if ci.ProcessName != "browser.exe" || ci.ProcessPath == "" {
				t.Fatal(ci)
			}
		} else if ci.ProcessName != "" || ci.ProcessPath != "" {
			t.Fatal("untrusted attribution leaked", ci)
		}
	}
}
