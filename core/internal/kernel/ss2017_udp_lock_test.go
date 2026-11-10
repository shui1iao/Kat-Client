package kernel

import (
	"bytes"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha1"

	SS "github.com/shui1iao/Kat/internal/ss"

	"net/netip"

	"testing"
)

func udpLockPacket(t *testing.T, codec *SS.Server, key []byte, source netip.AddrPort) *SS.Packet {
	t.Helper()
	salt := bytes.Repeat([]byte{0x63}, 16)
	sub, e := hkdf.Key(sha1.New, key, salt, "ss-subkey", 16)
	if e != nil {
		t.Fatal(e)
	}
	block, e := aes.NewCipher(sub)
	if e != nil {
		t.Fatal(e)
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	address, _ := (SS.Address{Host: "127.0.0.1", Port: 80}).MarshalBinary()
	wire := append(salt, a.Seal(nil, make([]byte, 12), append(address, []byte("request")...), nil)...)
	p, e := codec.DecodeUDP(wire, source)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
