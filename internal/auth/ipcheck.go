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
// When trustForwarded is true it reads X-Forwarded-For (set by Traefik).
func ClientIP(r *http.Request, trustForwarded bool) net.IP {
	if trustForwarded {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// X-Forwarded-For may be a comma-separated list; leftmost is the client.
			parts := strings.SplitN(xff, ",", 2)
			if ip := net.ParseIP(strings.TrimSpace(parts[0])); ip != nil {
				return ip
			}
		}
		if xri := r.Header.Get("X-Real-Ip"); xri != "" {
			if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
				return ip
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// No port in RemoteAddr (shouldn't happen but handle gracefully).
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}
