package sniff

import "testing"

func buildTestTLSClientHello(sni string) []byte {
	host := []byte(sni)
	nameEntry := make([]byte, 3+len(host))
	nameEntry[0] = 0
	nameEntry[1] = byte(len(host) >> 8)
	nameEntry[2] = byte(len(host))
	copy(nameEntry[3:], host)

	nameList := make([]byte, 2+len(nameEntry))
	nameList[0] = byte(len(nameEntry) >> 8)
	nameList[1] = byte(len(nameEntry))
	copy(nameList[2:], nameEntry)

	ext := make([]byte, 4+len(nameList))
	ext[0], ext[1] = 0, 0
	ext[2] = byte(len(nameList) >> 8)
	ext[3] = byte(len(nameList))
	copy(ext[4:], nameList)

	exts := make([]byte, 2+len(ext))
	exts[0] = byte(len(ext) >> 8)
	exts[1] = byte(len(ext))
	copy(exts[2:], ext)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, exts...)

	hs := make([]byte, 4+len(body))
	hs[0] = 1
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x01
	rec[3] = byte(len(hs) >> 8)
	rec[4] = byte(len(hs))
	copy(rec[5:], hs)
	return rec
}

func BenchmarkSniffTLSClientHello(b *testing.B) {
	pkt := buildTestTLSClientHello("sub.api.example.com")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host, st := TLSClientHello(pkt)
		if st != Done || host != "sub.api.example.com" {
			b.Fatalf("got (%q, %v)", host, st)
		}
	}
}

func BenchmarkSniffHTTPHost(b *testing.B) {
	req := []byte("GET /v1/resource HTTP/1.1\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n" +
		"Accept: application/json, text/plain, */*\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"Connection: keep-alive\r\n" +
		"X-Request-ID: 12345678-1234-1234-1234-1234567890ab\r\n" +
		"Host: Sub.Api.Example.COM:8080\r\n\r\n")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host, st := HTTPHost(req)
		if st != Done || host != "sub.api.example.com" {
			b.Fatalf("got (%q, %v)", host, st)
		}
	}
}
