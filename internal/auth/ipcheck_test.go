package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alanaktion/lilath/internal/auth"
)

func newIPChecker(t *testing.T, entries ...string) *auth.IPChecker {
	t.Helper()
	c, err := auth.NewIPChecker(entries)
	if err != nil {
		t.Fatalf("NewIPChecker(%v): %v", entries, err)
	}
	return c
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		xff            string
		xRealIP        string
		trustForwarded bool
		trustedProxies []string
		want           string
	}{
		{
			name:       "no forwarding trust uses peer",
			remoteAddr: "203.0.113.9:1234",
			xff:        "10.0.0.1",
			want:       "203.0.113.9",
		},
		{
			// The leftmost entry is whatever the client sent: proxies append, so
			// trusting it would let any request claim any source address.
			name:           "spoofed leftmost entry is ignored",
			remoteAddr:     "127.0.0.1:1234",
			xff:            "10.0.0.1, 203.0.113.9",
			trustForwarded: true,
			want:           "203.0.113.9",
		},
		{
			name:           "single entry from a trusted proxy is the client",
			remoteAddr:     "127.0.0.1:1234",
			xff:            "203.0.113.9",
			trustForwarded: true,
			trustedProxies: []string{"127.0.0.1"},
			want:           "203.0.113.9",
		},
		{
			name:           "headers from an untrusted peer are ignored",
			remoteAddr:     "203.0.113.9:1234",
			xff:            "10.0.0.1",
			trustForwarded: true,
			trustedProxies: []string{"127.0.0.1"},
			want:           "203.0.113.9",
		},
		{
			name:           "trusted proxies in the chain are skipped",
			remoteAddr:     "127.0.0.1:1234",
			xff:            "10.0.0.1, 203.0.113.9, 192.0.2.7",
			trustForwarded: true,
			trustedProxies: []string{"127.0.0.1", "192.0.2.0/24"},
			want:           "203.0.113.9",
		},
		{
			name:           "all entries trusted falls back to the peer",
			remoteAddr:     "127.0.0.1:1234",
			xff:            "192.0.2.7",
			trustForwarded: true,
			trustedProxies: []string{"127.0.0.1", "192.0.2.0/24"},
			want:           "127.0.0.1",
		},
		{
			name:           "malformed entry stops the walk",
			remoteAddr:     "127.0.0.1:1234",
			xff:            "10.0.0.1, not-an-ip",
			trustForwarded: true,
			want:           "127.0.0.1",
		},
		{
			name:           "entry with a port is parsed",
			remoteAddr:     "127.0.0.1:1234",
			xff:            "203.0.113.9:4321",
			trustForwarded: true,
			want:           "203.0.113.9",
		},
		{
			name:           "x-real-ip used when xff is absent",
			remoteAddr:     "127.0.0.1:1234",
			xRealIP:        "203.0.113.9",
			trustForwarded: true,
			want:           "203.0.113.9",
		},
		{
			name:           "x-real-ip ignored from an untrusted peer",
			remoteAddr:     "203.0.113.9:1234",
			xRealIP:        "10.0.0.1",
			trustForwarded: true,
			trustedProxies: []string{"127.0.0.1"},
			want:           "203.0.113.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/auth", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-Ip", tt.xRealIP)
			}

			got := auth.ClientIP(r, tt.trustForwarded, newIPChecker(t, tt.trustedProxies...))
			if got == nil {
				t.Fatalf("ClientIP returned nil, want %s", tt.want)
			}
			if got.String() != tt.want {
				t.Errorf("ClientIP = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestClientIP_SpoofedXFFDoesNotMatchAllowlist is the concrete bypass this
// guards against: a request that claims to come from an allowlisted internal
// address must not be granted the allowlist's blanket 200.
func TestClientIP_SpoofedXFFDoesNotMatchAllowlist(t *testing.T) {
	allowlist := newIPChecker(t, "10.0.0.0/8")

	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	r.RemoteAddr = "127.0.0.1:1234" // the proxy
	r.Header.Set("X-Forwarded-For", "10.0.0.5, 203.0.113.9")

	ip := auth.ClientIP(r, true, newIPChecker(t, "127.0.0.1"))
	if allowlist.Allow(ip) {
		t.Fatalf("client IP %s matched the allowlist via a spoofed X-Forwarded-For entry", ip)
	}
}
