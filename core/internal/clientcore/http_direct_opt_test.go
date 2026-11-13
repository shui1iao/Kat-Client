package clientcore

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDirectHTTPBridgeConnectAndPlainHTTPThroughKernel(t *testing.T) {
	payload := bytes.Repeat([]byte("direct-http-kernel-payload-64k!"), 4096)
	echoLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, e := echoLn.Accept()
			if e != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload[:4096])
	}))
	defer httpSrv.Close()

	h := newHost(t)
	text := fixture(t, map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	defer h.Stop()

	if h.bridge.directServer.Load() == nil {
		t.Fatal("directServer not bound on Host.Start")
	}

	// 1) CONNECT tunnel with buffered pre-read bytes + half-close
	conn, err := net.Dial("tcp4", portAddress(h.doc.client.HTTPPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	dst := echoLn.Addr().String()
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dst, dst)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, werr := conn.Write(payload)
		if werr == nil {
			werr = conn.(*net.TCPConn).CloseWrite()
		}
		errCh <- werr
	}()
	got, rerr := io.ReadAll(br)
	if werr := <-errCh; werr != nil || rerr != nil || !bytes.Equal(got, payload) {
		t.Fatalf("CONNECT mismatch: werr=%v rerr=%v len=%d", werr, rerr, len(got))
	}

	// 2) Plain HTTP proxy request via direct kernel dial
	proxyURL, _ := url.Parse("http://" + portAddress(h.doc.client.HTTPPort))
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := cl.Get(httpSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || !bytes.Equal(body, payload[:4096]) {
		t.Fatalf("plain HTTP failed: err=%v code=%d len=%d", err, resp.StatusCode, len(body))
	}

	// 3) Verify connection logs recorded system_proxy inbound kind
	logs := h.connectionLogs.read(0, 50)
	foundSysProxy := false
	for _, entry := range logs.Entries {
		if entry.InboundKind == "system_proxy" && strings.HasPrefix(entry.SourceAddr, "127.0.0.1:") {
			foundSysProxy = true
			break
		}
	}
	if !foundSysProxy {
		t.Fatalf("expected system_proxy InboundKind in connection logs, got %+v", logs.Entries)
	}
}
