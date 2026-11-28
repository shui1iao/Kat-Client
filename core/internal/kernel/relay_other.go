//go:build !linux

package kernel

import "net"

func tcpPairProgress(_, _ net.Conn) (uint64, bool) {
	return 0, false
}
