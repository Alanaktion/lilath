package auth

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// IPChecker holds a list of allowed IPs and CIDR ranges.
type IPChecker struct {
	nets []*net.IPNet
	ips  []net.IP
}

// NewIPChecker parses the allowlist entries, each of which may be a plain IP
// address or a CIDR range (e.g. "192.168.1.1" or "10.0.0.0/8").
func NewIPChecker(allowlist []string) (*IPChecker, error) {
	c := &IPChecker{}
	for _, entry := range allowlist {
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", entry, err)
			}
			c.nets = append(c.nets, ipNet)
		} else {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address %q", entry)
			}
			c.ips = append(c.ips, ip)
		}
	}
	return c, nil
}

// IsEmpty reports whether the allowlist has no entries (i.e. allowlisting is
// disabled and all IPs should fall through to credential auth).
func (c *IPChecker) IsEmpty() bool {
	return len(c.nets) == 0 && len(c.ips) == 0
}

// Allow reports whether ip is in the allowlist.
func (c *IPChecker) Allow(ip net.IP) bool {
	for _, allowed := range c.ips {
		if allowed.Equal(ip) {
			return true
		}
	}
	for _, network := range c.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP extracts the real client IP from the request.
//
// When trustForwarded is false, only the transport-level peer address is used.
//
// When trustForwarded is true, X-Forwarded-For is consulted, but only the
// portion of it that a proxy can be trusted to have written. The header is
// walked from the right (most recently appended, i.e. added by the nearest
// proxy) and the first address that is not itself a trusted proxy is returned.
// The leftmost entry is deliberately *not* used: a client can send its own
// X-Forwarded-For, and proxies append rather than replace, so the leftmost
// entry is attacker-controlled. Using it would let a request claim any source
// address and defeat both the IP allowlist and per-IP rate limiting.
//
// When trustedProxies is non-empty, forwarding headers are additionally ignored
// unless the request's peer is one of those proxies.
func ClientIP(r *http.Request, trustForwarded bool, trustedProxies *IPChecker) net.IP {
	peer := peerIP(r)
	if !trustForwarded {
		return peer
	}

	trusted := func(ip net.IP) bool {
		return trustedProxies != nil && !trustedProxies.IsEmpty() && trustedProxies.Allow(ip)
	}

	// Only honour forwarding headers from a known proxy, when one is configured.
	if trustedProxies != nil && !trustedProxies.IsEmpty() {
		if peer == nil || !trustedProxies.Allow(peer) {
			return peer
		}
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := parseIP(strings.TrimSpace(parts[i]))
			if ip == nil {
				// A malformed entry means everything to its left is untrustworthy.
				break
			}
			if trusted(ip) {
				continue
			}
			return ip
		}
		// Every entry was a trusted proxy (or the header was malformed): fall
		// back to the peer rather than trusting a client-supplied value.
		return peer
	}

	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		if ip := parseIP(strings.TrimSpace(xri)); ip != nil {
			return ip
		}
	}

	return peer
}

// peerIP returns the IP of the immediate transport peer.
func peerIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// No port in RemoteAddr (shouldn't happen but handle gracefully).
		host = r.RemoteAddr
	}
	return parseIP(host)
}

// parseIP parses an IP address that may carry a port or an IPv6 zone.
func parseIP(s string) net.IP {
	if s == "" {
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	// Some proxies write "host:port" or "[v6]:port" entries.
	if host, _, err := net.SplitHostPort(s); err == nil {
		return net.ParseIP(host)
	}
	return nil
}
