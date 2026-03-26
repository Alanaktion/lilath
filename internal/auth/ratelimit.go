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

// Allow reports whether a new request identified by key is within the rate
// limit. The key is typically a client IP address string.
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

// AllowIP is a convenience wrapper that calls Allow with ip.String().
func (rl *RateLimiter) AllowIP(ip net.IP) bool {
	return rl.Allow(ip.String())
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
