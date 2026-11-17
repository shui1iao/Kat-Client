package sniff

import (
	"encoding/binary"
	"testing"
)

func buildRawSNIClientHelloRecord(rawSNI string) []byte {
	nameBytes := []byte(rawSNI)
	// server_name entry: name_type(0) + uint16 len + nameBytes
	var list []byte
	list = append(list, 0x00)
	list = binary.BigEndian.AppendUint16(list, uint16(len(nameBytes)))
	list = append(list, nameBytes...)

	// server_name extension data: uint16 list_len + list
	var extData []byte
	extData = binary.BigEndian.AppendUint16(extData, uint16(len(list)))
	extData = append(extData, list...)

	// extensions block: ext_type(0) + uint16 ext_len + extData
	var exts []byte
	exts = binary.BigEndian.AppendUint16(exts, 0x0000)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(extData)))
	exts = append(exts, extData...)

	// ClientHello body: legacy_version(0x0303) + random(32) + sid(0) + cipher_suites(2 bytes: 0x1301) + comp_methods(1 byte: 0) + extensions
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	// Handshake message: type(1) + uint24 len + body
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	// TLS record: ContentType(0x16) + legacy_record_version(0x0301) + uint16 len + hs
	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	rec = append(rec, hs...)
	return rec
}

func TestStreamRawAndQUICAddRawPreserveLiteralSNI(t *testing.T) {
	tlsRec := buildRawSNIClientHelloRecord("Mijia Cloud")
	proto, host, rawHost, st := StreamRaw(tlsRec)
	if st != Done || proto != ProtoTLS || host != "" || rawHost != "Mijia Cloud" {
		t.Fatalf("StreamRaw TLS Mijia Cloud: proto=%q host=%q rawHost=%q st=%v", proto, host, rawHost, st)
	}

	httpReq := []byte("GET / HTTP/1.1\r\nHost: Mijia Cloud:8080\r\n\r\n")
	proto, host, rawHost, st = StreamRaw(httpReq)
	if st != Done || proto != ProtoHTTP || host != "" || rawHost != "Mijia Cloud" {
		t.Fatalf("StreamRaw HTTP Mijia Cloud: proto=%q host=%q rawHost=%q st=%v", proto, host, rawHost, st)
	}

	hs := tlsRec[5:]
	var cryptoFrame []byte
	cryptoFrame = append(cryptoFrame, 0x06) // CRYPTO frame
	cryptoFrame = appendVarintTest(cryptoFrame, 0)
	cryptoFrame = appendVarintTest(cryptoFrame, uint64(len(hs)))
	cryptoFrame = append(cryptoFrame, hs...)
	pkt := sealInitial(t, quicV1, []byte{1, 2, 3, 4, 5, 6, 7, 8}, 1, cryptoFrame)
	var q QUIC
	qHost, qRaw, qSt := q.AddRaw(pkt)
	if qSt != Done || qHost != "" || qRaw != "Mijia Cloud" {
		t.Fatalf("QUIC.AddRaw Mijia Cloud: host=%q rawHost=%q st=%v", qHost, qRaw, qSt)
	}
}

func appendVarintTest(b []byte, v uint64) []byte {
	if v < 64 {
		return append(b, byte(v))
	}
	return append(b, 0x40|byte(v>>8), byte(v))
}
