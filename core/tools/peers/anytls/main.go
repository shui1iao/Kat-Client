// Separate test-only executable: all AnyTLS session processing comes from the
// stable upstream library. No production package import, no copied codec code.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	A "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	address := flag.String("server", "", "")
	cert := flag.String("ca", "", "")
	targetString := flag.String("target", "", "loopback target")
	secondString := flag.String("second-target", "", "second loopback UDP target")
	mode := flag.String("mode", "client-first", "")
	flag.Parse()
	target := M.ParseSocksaddr(*targetString)
	if !target.IsIP() || !target.Addr.IsLoopback() {
		return fmt.Errorf("loopback target only")
	}
	host, _, e := net.SplitHostPort(*address)
	if e != nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("loopback only")
	}
	roots := x509.NewCertPool()
	pem, e := os.ReadFile(*cert)
	if e != nil {
		return e
	}
	if *mode != "trust-rejection" && !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("bad CA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	dial := func(ctx context.Context) (net.Conn, error) {
		raw, e := (&net.Dialer{}).DialContext(ctx, "tcp", *address)
		if e != nil {
			return nil, e
		}
		c := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13})
		if e = c.HandshakeContext(ctx); e != nil {
			raw.Close()
			return nil, e
		}
		return c, nil
	}
	if *mode == "trust-rejection" {
		conn, e := dial(ctx)
		if e == nil {
			conn.Close()
			return fmt.Errorf("untrusted certificate accepted")
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": *mode, "status": "PASS", "verified_rejection": true})
	}
	if *mode == "concurrent" {
		raw, e := dial(ctx)
		if e != nil {
			return e
		}
		defer raw.Close()
		sum := sha256.Sum256([]byte("fixture-password"))
		auth := append([]byte(nil), sum[:]...)
		auth = binary.BigEndian.AppendUint16(auth, 30)
		p := make([]byte, 30)
		if _, e = rand.Read(p); e != nil {
			return e
		}
		auth = append(auth, p...)
		if _, e = raw.Write(auth); e != nil {
			return e
		}
		var factory atomic.TypedValue[*padding.PaddingFactory]
		factory.Store(padding.NewPaddingFactory([]byte("stop=3\n0=30-30\n1=100-200\n2=200-300")))
		// Run initializes buffered settings synchronously and starts recvLoop.
		// It must precede all OpenStream calls; it is not a blocking recv loop.
		sess := session.NewClientSession(raw, &factory, logger.NOP())
		sess.Run()
		defer sess.Close()

		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for i := 0; i < 4; i++ {
			// OpenStream allocates IDs and sends SYN in this order; concurrent
			// payload exchange remains on one session. Do not race upstream
			// ID allocation against its separately locked control write.
			st, e := sess.OpenStream()
			if e != nil {
				return e
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer st.Close()
				st.SetDeadline(time.Now().Add(8 * time.Second))
				if e = M.SocksaddrSerializer.WriteAddrPort(st, target); e != nil {
					errs <- e
					return
				}
				errs <- exchange(st, false)
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			if e != nil {
				return e
			}
		}
	} else {
		client, e := A.NewClient(ctx, A.ClientConfig{Password: "fixture-password", DialOut: dial, Logger: logger.NOP()})
		if e != nil {
			return e
		}
		defer client.Close()
		if *mode == "udp-connect" || *mode == "udp-nonconnect" {
			raw, e := client.CreateProxy(ctx, uot.RequestDestination(2))
			if e != nil {
				return e
			}
			defer raw.Close()
			connected := *mode == "udp-connect"
			target := M.ParseSocksaddr(*targetString)
			request := uot.Request{IsConnect: connected, Destination: target}
			if e = uot.WriteRequest(raw, request); e != nil {
				return e
			}
			udp := uot.NewConn(raw, request)
			for i := 0; i < 3; i++ {
				dest := target
				if !connected && i == 1 {
					dest = M.ParseSocksaddr(*secondString)
					if !dest.IsIP() || !dest.Addr.IsLoopback() {
						return fmt.Errorf("loopback second target only")
					}
				}
				p := bytes.Repeat([]byte{byte(i + 1)}, 1200)
				if _, e = udp.WriteTo(p, dest.UDPAddr()); e != nil {
					return e
				}
				b := make([]byte, 2048)
				n, addr, e := udp.ReadFrom(b)
				if e != nil {
					return e
				}
				if !bytes.Equal(b[:n], p) || addr.String() != dest.String() {
					return fmt.Errorf("UDP mismatch %s", addr)
				}
			}
		} else {
			rounds := 1
			if *mode == "reuse" {
				rounds = 2
			}
			for i := 0; i < rounds; i++ {
				serverFirst := *mode == "server-first"
				if serverFirst {

				}
				st, e := client.CreateProxy(ctx, target)
				if e != nil {
					return e
				}
				st.SetDeadline(time.Now().Add(8 * time.Second))
				e = exchange(st, serverFirst)
				st.Close()
				if e != nil {
					return e
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": *mode, "peer": "anytls/sing-anytls@v0.0.11", "status": "PASS"})
}
func exchange(st io.ReadWriter, first bool) error {
	if first {
		p := make([]byte, 7)
		if _, e := io.ReadFull(st, p); e != nil {
			return e
		}
		if string(p) != "welcome" {
			return fmt.Errorf("wrong greeting")
		}
	}
	data := bytes.Repeat([]byte{0x42}, 80000)
	for off := 0; off < len(data); {
		end := min(off+4096, len(data))
		if _, e := st.Write(data[off:end]); e != nil {
			return e
		}
		off = end
	}
	p := make([]byte, len(data))
	if _, e := io.ReadFull(st, p); e != nil {
		return e
	}
	if !bytes.Equal(p, data) {
		return fmt.Errorf("TCP mismatch")
	}
	return nil
}
