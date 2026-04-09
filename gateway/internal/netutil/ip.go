package netutil

import "net"

// ClientIP returns the client IP without port.
// If parsing fails, it returns the original remote address.
func ClientIP(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return ip
}
