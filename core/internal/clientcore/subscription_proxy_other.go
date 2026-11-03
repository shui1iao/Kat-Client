//go:build !windows

package clientcore

import "net"

// No production non-Windows system-proxy discovery exists. Tests use an explicit seam below.
func verifyBootstrapPeer(c net.Conn) error { return dl("proxy_connect", "proxy_identity_unknown") }
