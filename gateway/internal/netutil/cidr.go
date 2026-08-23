package netutil

import (
	"fmt"
	"net"
	"strings"
)

// ParseCIDRs turns a list of CIDRs or bare addresses into networks.
//
// Three places need this -- the trusted-proxy list, the reflex's exempt ranges
// and the rate limiter's -- and they must agree on what a written entry means.
// A list that trusts "10.0.0.1" in one place and rejects it in another is the
// kind of difference nobody finds until an address is treated the wrong way.
//
// `what` names the setting, so the error says which list the bad entry is in.
func ParseCIDRs(entries []string, what string) ([]*net.IPNet, error) {
	var networks []*net.IPNet

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// A bare address is the obvious thing to write, so accept it rather
		// than silently ignoring the entry -- which, depending on the list,
		// would quietly trust nothing or exempt nobody.
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid %s %q", what, entry)
			}
			if ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}

		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid %s %q: %w", what, entry, err)
		}
		networks = append(networks, network)
	}

	return networks, nil
}

// NetworksContain reports whether any network holds the address.
//
// An address that will not parse is not contained by anything. Every caller
// wants that answer: an unparseable address is not a trusted proxy, and it is
// not exempt from anything either.
func NetworksContain(networks []*net.IPNet, ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, network := range networks {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}
