// Test-only RFC8446 KeyUpdate construction, with fixed upstream Xray REALITY
// authentication. Filtering optional compatibility CCS does not alter transcript.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	xn "github.com/xtls/xray-core/common/net"
	xr "github.com/xtls/xray-core/transport/internet/reality"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

type reviewNoCCSConn struct {
	net.Conn
	omit                 bool
	suppressed, observed int
}

func (c *reviewNoCCSConn) Write(p []byte) (int, error) {
	var wire []byte
	for off := 0; off < len(p); {
		if len(p)-off < 5 {
			return 0, fmt.Errorf("partial record write")
		}
		n := 5 + int(binary.BigEndian.Uint16(p[off+3:off+5]))
		if off+n > len(p) {
			return 0, fmt.Errorf("split record write")
		}
		r := p[off : off+n]
		if bytes.Equal(r, []byte{20, 3, 3, 0, 1, 1}) {
			c.observed++
			if c.omit {
				c.suppressed++
				off += n
				continue
			}
		}
		wire = append(wire, r...)
		off += n
	}
	for len(wire) > 0 {
		n, e := c.Conn.Write(wire)
		if e != nil {
			return 0, e
		}
		if n == 0 {
			return 0, io.ErrShortWrite
		}
		wire = wire[n:]
	}
	return len(p), nil
}
func reviewExpand(h func() hash.Hash, secret []byte, label string, n int) []byte {
	s := []byte("tls13 " + label)
	info := append([]byte{byte(n >> 8), byte(n), byte(len(s))}, s...)
	info = append(info, 0)
	out := make([]byte, n)
	_, e := io.ReadFull(hkdf.Expand(h, secret, info), out)
	check(e)
	return out
}
func reviewSeal(suite uint16, secret, p []byte) []byte {
	hf := sha256.New
	keyLen := 16
	if suite == tls.TLS_AES_256_GCM_SHA384 {
		hf = sha512.New384
		keyLen = 32
	} else if suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		keyLen = 32
	}
	key := reviewExpand(hf, secret, "key", keyLen)
	iv := reviewExpand(hf, secret, "iv", 12)
	var a cipher.AEAD
	var e error
	if suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		a, e = chacha20poly1305.New(key)
	} else {
		b, err := aes.NewCipher(key)
		check(err)
		a, e = cipher.NewGCM(b)
	}
	check(e)
	n := len(p) + a.Overhead()
	header := []byte{23, 3, 3, byte(n >> 8), byte(n)}
	return a.Seal(header, iv, p, header)
}
func reviewKeyUpdate() {
	var cfg struct {
		Front, PublicKey string
		OmitCCS          bool
	}
	check(json.NewDecoder(os.Stdin).Decode(&cfg))
	pub, e := base64.RawURLEncoding.DecodeString(cfg.PublicKey)
	check(e)
	keyfile, e := os.CreateTemp(".", ".review-keylog-*")
	check(e)
	path := keyfile.Name()
	check(keyfile.Close())
	defer os.Remove(path)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, e := (&net.Dialer{}).DialContext(ctx, "tcp", cfg.Front)
	check(e)
	defer raw.Close()
	check(raw.SetDeadline(time.Now().Add(5 * time.Second)))
	filtered := &reviewNoCCSConn{Conn: raw, omit: cfg.OmitCCS}
	secure, e := xr.UClient(filtered, &xr.Config{ServerName: "front.test", PublicKey: pub, ShortId: []byte{1}, Fingerprint: "chrome", MasterKeyLog: path}, ctx, xn.TCPDestination(xn.LocalHostIP, 1))
	check(e)
	u, ok := secure.(*xr.UConn)
	if !ok || !u.Verified {
		panic("REALITY HMAC not verified")
	}
	if cfg.OmitCCS && filtered.suppressed == 0 {
		panic("CCS omission not exercised")
	}
	fmt.Printf("REALITY_VERIFIED omit_ccs=%v observed=%d suppressed=%d\n", cfg.OmitCCS, filtered.observed, filtered.suppressed)
	logs, e := os.ReadFile(path)
	check(e)
	var secret []byte
	for _, line := range strings.Split(string(logs), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "CLIENT_TRAFFIC_SECRET_0" {
			secret, e = hex.DecodeString(f[2])
			check(e)
			break
		}
	}
	if len(secret) == 0 {
		panic("missing traffic secret")
	}
	suite := u.ConnectionState().CipherSuite
	packet := reviewSeal(suite, secret, []byte{24, 0, 0, 1, 0, 22})
	_, e = raw.Write(packet)
	check(e)
	hf := sha256.New
	if suite == tls.TLS_AES_256_GCM_SHA384 {
		hf = sha512.New384
	}
	next := reviewExpand(hf, secret, "traffic upd", hf().Size())
	packet = reviewSeal(suite, next, append([]byte("probe"), 23))
	_, e = raw.Write(packet)
	check(e)
	b := make([]byte, 5)
	_, e = io.ReadFull(secure, b)
	check(e)
	if string(b) != "reply" {
		panic("plaintext mismatch")
	}
	fmt.Println("REALITY_KEYUPDATE_REPLY_PASS")
}
