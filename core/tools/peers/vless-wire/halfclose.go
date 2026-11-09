package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/xtls/xray-core/common/buf"
	xn "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	xr "github.com/xtls/xray-core/transport/internet/reality"
	"io"
	"net"
	"os"
	"time"
)

type halfConfig struct{ Front, Target, Mode, Flow, Certificate, PublicKey string }

func check(e error) {
	if e != nil {
		panic(e)
	}
}
func halfclose() {
	var cfg halfConfig
	check(json.NewDecoder(os.Stdin).Decode(&cfg))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp", cfg.Front)
	check(e)
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	var secure net.Conn
	if cfg.Mode == "tls" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(cfg.Certificate)) {
			panic("root")
		}
		tc := tls.Client(c, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13})
		check(tc.HandshakeContext(ctx))
		secure = tc
	} else {
		pub, e := base64.RawURLEncoding.DecodeString(cfg.PublicKey)
		check(e)
		secure, e = xr.UClient(c, &xr.Config{ServerName: "localhost", PublicKey: pub, ShortId: []byte{1}, Fingerprint: "chrome"}, ctx, xn.TCPDestination(xn.LocalHostIP, 1))
		check(e)
	}
	id, e := uuid.ParseString("4a86ae32-2235-4dc3-b103-42a2d162d73c")
	check(e)
	a, e := xn.ParseDestination("tcp:" + cfg.Target)
	check(e)
	account := &vless.MemoryAccount{ID: protocol.NewID(id), Flow: cfg.Flow}
	req := &protocol.RequestHeader{Version: 0, Command: protocol.RequestCommandTCP, Address: a.Address, Port: a.Port, User: &protocol.MemoryUser{Account: account}}
	addons := &encoding.Addons{Flow: cfg.Flow}
	check(encoding.EncodeRequestHeader(secure, req, addons))
	_, e = encoding.DecodeResponseHeader(secure, req)
	check(e)
	var reader io.Reader = secure
	writer := buf.NewWriter(secure)
	state := proxy.NewTrafficState(id.Bytes())
	if cfg.Flow == vless.XRV {
		vr := proxy.NewVisionReader(buf.NewReader(secure), state, false, ctx, secure, nil, nil, nil)
		reader = &buf.BufferedReader{Reader: vr}
		writer = proxy.NewVisionWriter(writer, state, true, ctx, secure, nil, nil)
	}
	r := bufio.NewReader(reader)
	line, e := r.ReadString(10)
	check(e)
	if line != "greeting-before-client\n" {
		panic(line)
	}
	check(writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("half-close-payload"))}))
	cw, ok := secure.(interface{ CloseWrite() error })
	if !ok {
		panic("no CloseWrite")
	}
	check(cw.CloseWrite())
	got, e := io.ReadAll(r)
	check(e)
	if string(got) != "reply:half-close-payload" {
		panic(fmt.Sprintf("reply %q", got))
	}
	fmt.Println("XRAY_WIRE_HALF_CLOSE_PASS", cfg.Mode, cfg.Flow)
}
