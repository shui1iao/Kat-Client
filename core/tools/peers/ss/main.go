// Independent TEST-ONLY executable. Protocol processing is wholly delegated to
// upstream sing-shadowsocks v0.2.7; package ss is neither imported nor linked.
// This harness calls public APIs, and contains no copied upstream codec code.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	S "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	method := flag.String("method", "", "")
	keyString := flag.String("key", "", "")
	server := flag.String("server", "", "")
	network := flag.String("network", "tcp", "")
	targetString := flag.String("target", "", "loopback echo target")
	first := flag.Bool("server-first", false, "")
	flag.Parse()
	host, _, err := net.SplitHostPort(*server)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("loopback only")
	}
	key, err := base64.StdEncoding.DecodeString(*keyString)
	if err != nil {
		return err
	}
	var codec S.Method
	if strings.HasPrefix(*method, "2022-") {
		codec, err = shadowaead_2022.New(*method, [][]byte{key}, time.Now)
	} else {
		codec, err = shadowaead.New(*method, key, "")
	}
	if err != nil {
		return err
	}
	raw, err := net.DialTimeout(*network, *server, 5*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	target := M.ParseSocksaddr(*targetString)
	if !target.IsIP() || !target.Addr.IsLoopback() {
		return fmt.Errorf("loopback target only")
	}
	if *network == "tcp" {
		var conn net.Conn
		if *first {
			conn, err = codec.DialConn(raw, target)
		} else {
			conn = codec.DialEarlyConn(raw, target)
		}
		if err != nil {
			return err
		}
		defer conn.Close()
		if *first {
			b := make([]byte, len("server-first"))
			if _, err = io.ReadFull(conn, b); err != nil {
				return err
			}
			if string(b) != "server-first" {
				return fmt.Errorf("wrong server-first greeting")
			}
		}
		p := bytes.Repeat([]byte{0x42}, 200000)
		// Upstream v0.2.7 initial-write API requires a bounded application write.
		// A 200000-byte initial Write panics upstream before sending any bytes;
		// split application writes, not wire bytes or the production codec.
		for off := 0; off < len(p); {
			end := min(off+16384, len(p))
			if _, err = conn.Write(p[off:end]); err != nil {
				return err
			}
			off = end
		}
		back := make([]byte, len(p))
		if _, err = io.ReadFull(conn, back); err != nil {
			return err
		}
		if !bytes.Equal(p, back) {
			return fmt.Errorf("TCP payload differs")
		}
	} else if *network == "udp" {
		conn := codec.DialPacketConn(raw)
		defer conn.Close()
		for i := 0; i < 3; i++ {
			p := bytes.Repeat([]byte{byte(i + 1)}, 1200)
			if _, err = conn.WriteTo(p, target.UDPAddr()); err != nil {
				return err
			}
			b := make([]byte, 2048)
			n, addr, e := conn.ReadFrom(b)
			if e != nil {
				return e
			}
			if !bytes.Equal(p, b[:n]) || addr.String() != target.String() {
				return fmt.Errorf("UDP reply differs %s", addr)
			}
		}
	} else {
		return fmt.Errorf("invalid network")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"method": *method, "network": *network, "server_first": *first, "peer": "github.com/sagernet/sing-shadowsocks@v0.2.7", "status": "PASS"})
}
