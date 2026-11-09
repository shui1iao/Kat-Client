package main

import (
	"context"
	"encoding/base64"
	"fmt"
	xn "github.com/xtls/xray-core/common/net"
	xr "github.com/xtls/xray-core/transport/internet/reality"
	"io"
	"net"
	"os"
	"time"
)

func authprobe() {
	if len(os.Args) != 5 {
		panic("authprobe address pub sni")
	}
	pub, e := base64.RawURLEncoding.DecodeString(os.Args[3])
	check(e)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp", os.Args[2])
	check(e)
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	s, e := xr.UClient(c, &xr.Config{ServerName: os.Args[4], PublicKey: pub, ShortId: []byte{1}, Fingerprint: "chrome"}, ctx, xn.TCPDestination(xn.LocalHostIP, 1))
	check(e)
	fmt.Println("XRAY_AUTH_VERIFIED")
	io.Copy(io.Discard, s)
}
