package udpmmsg

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestBatchV4AndLargeDatagram(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	srvRaw, _ := srv.SyscallConn()
	cliRaw, _ := cli.SyscallConn()
	dst := srv.LocalAddr().(*net.UDPAddr).AddrPort()
	const count = 20
	pkts := make([][]byte, count)
	addrs := make([]netip.AddrPort, count)
	for i := 0; i < count; i++ {
		sz := 1200
		if i == count-1 {
			sz = 8192
		}
		pkts[i] = bytes.Repeat([]byte{byte(i + 1)}, sz)
		addrs[i] = dst
	}
	var sb SendBatch
	if sent, err := WriteBatch(cli, cliRaw, false, &sb, pkts, addrs); err != nil || sent != count {
		t.Fatalf("WriteBatch sent=%d err=%v", sent, err)
	}
	rb := AcquireRecvBatch()
	defer ReleaseRecvBatch(rb)
	_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := 0
	for got < count {
		n, err := ReadBatch(srv, srvRaw, rb)
		if err != nil {
			t.Fatalf("ReadBatch err=%v", err)
		}
		for i := 0; i < n; i++ {
			if !bytes.Equal(rb.Bufs[i][:rb.Lens[i]], pkts[got]) {
				t.Fatalf("pkt %d mismatch", got)
			}
			got++
		}
	}
}
