package auth

import (
	"net"
	"sync"
	"time"
)

// RateLimiter is a per-key fixed-window counter-based rate limiter.
// All methods are safe for concurrent use.
type RateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]*rlEntry
}

type rlEntry struct {
	count   int
	resetAt time.Time
}

// NewRateLimiter creates a new rate limiter allowing at most limit requests per
// window. When limit is 0, Allow always returns true (rate limiting disabled).
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	// A negative limit is a misconfiguration; treat it the same as 0 (disabled)
	// rather than rejecting every request.
	if limit < 0 {
		limit = 0
	}
	if window <= 0 {
		window = time.Minute
	}
	rl := &RateLimiter{
		limit:   limit,
		window:  window,
		entries: make(map[string]*rlEntry),
	}
	if limit > 0 {
		go rl.cleanupLoop()
	}
	return rl
}

// Allow counts a request identified by key and reports whether it is within the
// rate limit. The key is typically a client IP address string.
func (rl *RateLimiter) Allow(key string) bool {
	if rl.limit == 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	e, ok := rl.entries[key]
	if !ok || now.After(e.resetAt) {
		rl.entries[key] = &rlEntry{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	e.count++
	return e.count <= rl.limit
}

// Peek reports whether a request for key would be within the rate limit,
// without counting it. Use it together with Record when only some outcomes of
// an operation should consume budget (for example, only failed credential
// checks).
func (rl *RateLimiter) Peek(key string) bool {
	if rl.limit == 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, ok := rl.entries[key]
	if !ok || time.Now().After(e.resetAt) {
		return true
	}
	return e.count < rl.limit
}

// Record counts a request for key against the limit, ignoring the result.
func (rl *RateLimiter) Record(key string) {
	rl.Allow(key)
}

// AllowIP is a convenience wrapper that calls Allow with the limiter key for ip.
func (rl *RateLimiter) AllowIP(ip net.IP) bool {
	return rl.Allow(Key(ip))
}

// PeekIP is a convenience wrapper that calls Peek with the limiter key for ip.
func (rl *RateLimiter) PeekIP(ip net.IP) bool {
	return rl.Peek(Key(ip))
}

// RecordIP is a convenience wrapper that calls Record with the limiter key for ip.
func (rl *RateLimiter) RecordIP(ip net.IP) {
	rl.Record(Key(ip))
}

// Key returns the rate-limit bucket for an IP address. IPv4 addresses get their
// own bucket; IPv6 addresses are grouped by /64 prefix, because a single client
// is routinely handed a whole /64 (or larger) and would otherwise be able to
// sidestep the limit entirely by using a fresh address per request.
func Key(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if v6 := ip.To16(); v6 != nil {
		return v6.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return ip.String()
}

// cleanupLoop removes expired entries periodically to prevent unbounded memory
// growth in long-running servers.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for k, e := range rl.entries {
			if now.After(e.resetAt) {
				delete(rl.entries, k)
			}
		}
		rl.mu.Unlock()
	}
}
