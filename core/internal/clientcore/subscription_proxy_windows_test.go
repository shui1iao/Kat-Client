//go:build windows

package clientcore

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func normalPeerHarness(t *testing.T) {
	t.Helper()
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("NORMAL_USER_REQUIRED")
	}
}

// Fixed helper modes only. No user-supplied PID, path, URL, command or bind address.
func TestBootstrapWindowsPeerHelper(t *testing.T) {
	mode := os.Getenv("KAT_BOOTSTRAP_PEER_HELPER")
	if mode == "" {
		t.Skip("internal helper only")
	}
	normalPeerHarness(t)
	network, address := "tcp4", "127.0.0.1:0"
	switch mode {
	case "v4-config":
		address = "127.0.0.1:7890"
	case "v4-random":
	case "v6-random":
		network, address = "tcp6", "[::1]:0"
	default:
		t.Fatal("INVALID_HELPER_MODE")
	}
	l, e := net.Listen(network, address)
	if e != nil {
		fmt.Println("UNAVAILABLE")
		return
	}
	defer l.Close()
	fmt.Printf("READY %d\n", l.Addr().(*net.TCPAddr).Port)
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, os.Stdin); l.Close(); close(done) }()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				r := bufio.NewReader(c)
				line, e := r.ReadString('\n')
				if e != nil || line != "CONNECT 8.8.8.8:443 HTTP/1.1\r\n" {
					return
				}
				for {
					line, e = r.ReadString('\n')
					if e != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
				io.Copy(io.Discard, r)
			}()
		}
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		l.Close()
	}
}
func TestBootstrapWindowsReadOnlyPeerAPI(t *testing.T) {
	normalPeerHarness(t)
	for _, mode := range []string{"v4-config", "v4-random", "v6-random"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			exe, e := os.Executable()
			if e != nil {
				t.Fatal("OWN_IMAGE_UNAVAILABLE")
			}
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestBootstrapWindowsPeerHelper$")
			cmd.Env = append(os.Environ(), "KAT_BOOTSTRAP_PEER_HELPER="+mode)
			output, e := cmd.StdoutPipe()
			if e != nil {
				t.Fatal("OWN_HELPER_PIPE")
			}
			input, e := cmd.StdinPipe()
			if e != nil {
				t.Fatal("OWN_HELPER_PIPE")
			}
			if cmd.Start() != nil {
				t.Fatal("OWN_HELPER_START")
			}
			defer func() { input.Close(); cancel(); cmd.Wait() }()
			scan := bufio.NewScanner(output)
			if !scan.Scan() {
				t.Fatal("OWN_HELPER_NO_READY")
			}
			line := scan.Text()
			if line == "UNAVAILABLE" {
				if mode == "v4-config" {
					t.Skip("PORT_7890_BUSY_OR_UNAVAILABLE_NOT_CHANGED; random port and synthetic configured-port regression remain")
				}
				if mode == "v6-random" {
					t.Skip("IPV6_LOOPBACK_UNAVAILABLE")
				}
				t.Fatal("LOOPBACK_UNAVAILABLE")
			}
			parts := strings.Fields(line)
			if len(parts) != 2 || parts[0] != "READY" {
				t.Fatal("OWN_HELPER_PROTOCOL")
			}
			port, e := strconv.ParseUint(parts[1], 10, 16)
			if e != nil || port == 0 {
				t.Fatal("OWN_HELPER_PROTOCOL")
			}
			host := "127.0.0.1"
			if mode == "v6-random" {
				host = "::1"
			}
			endpoint := &bootstrapProxy{Host: host, Port: uint16(port)}
			c, e := net.DialTimeout("tcp", net.JoinHostPort(host, parts[1]), time.Second)
			if e != nil {
				t.Fatal("OWN_HELPER_CONNECT")
			}
			pid, e := bootstrapPeerPID(c)
			if e != nil || pid != uint32(cmd.Process.Pid) {
				c.Close()
				t.Fatal("EXACT_REVERSE_TUPLE_PID_MISMATCH")
			}
			if verifyBootstrapPeer(c) != nil {
				c.Close()
				t.Fatal("THIRD_PARTY_PEER_REFUSED")
			}
			c.Close()
			tunnel, e := dialBootstrap(ctx, "8.8.8.8:443", endpoint, nil, func(context.Context, string) ([]netip.Addr, error) { return nil, fmt.Errorf("unused") }, []int{7890, 7891})
			if e != nil {
				t.Fatal("PRODUCTION_THIRD_PARTY_CONNECT_FAILED")
			}
			tunnel.Close()
		})
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run("self-"+network, func(t *testing.T) {
			host := "127.0.0.1"
			if network == "tcp6" {
				host = "::1"
			}
			l, e := net.Listen(network, net.JoinHostPort(host, "0"))
			if e != nil {
				if network == "tcp6" {
					t.Skip("IPV6_LOOPBACK_UNAVAILABLE")
				}
				t.Fatal("SELF_LISTEN")
			}
			defer l.Close()
			read := make(chan int, 1)
			go func() {
				c, e := l.Accept()
				if e != nil {
					read <- 0
					return
				}
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				var b [1]byte
				n, _ := c.Read(b[:])
				read <- n
			}()
			_, e = dialBootstrap(context.Background(), "8.8.8.8:443", &bootstrapProxy{Host: host, Port: uint16(l.Addr().(*net.TCPAddr).Port)}, nil, func(context.Context, string) ([]netip.Addr, error) { return nil, fmt.Errorf("unused") }, nil)
			assertDetail(t, e, "proxy_connect", "self_loop")
			if <-read != 0 {
				t.Fatal("CONNECT_BYTES_SENT_TO_SELF")
			}
		})
	}
	// A real table query with an impossible reverse peer port must fail closed.
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal("UNKNOWN_LISTEN")
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(io.Discard, c)
		}
	}()
	c, e := net.Dial("tcp4", l.Addr().String())
	if e != nil {
		t.Fatal("UNKNOWN_CONNECT")
	}
	defer c.Close()
	assertDetail(t, verifyBootstrapPeer(impossiblePeer{c}), "proxy_connect", "proxy_identity_unknown")
	report, _ := json.Marshal(map[string]any{"normal_user": true, "real_TCP_table": true, "external_network": false, "changed_settings": false, "self_before_CONNECT_refused": true})
	t.Log(string(report))
}

type impossiblePeer struct{ net.Conn }

func (c impossiblePeer) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}
