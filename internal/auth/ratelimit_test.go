package auth

import (
	"net"
	"testing"
	"time"
)

func TestNewRateLimiter_ZeroLimit(t *testing.T) {
	rl := NewRateLimiter(0, time.Minute)
	for i := 0; i < 100; i++ {
		if !rl.Allow("key") {
			t.Fatalf("Allow returned false with limit=0 (disabled)")
		}
	}
}

func TestRateLimiter_AllowsUpToLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	for i := 1; i <= 3; i++ {
		if !rl.Allow("ip1") {
			t.Fatalf("request %d should be allowed, got denied", i)
		}
	}
}

func TestRateLimiter_BlocksAboveLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		rl.Allow("ip1")
	}
	if rl.Allow("ip1") {
		t.Fatal("4th request should be blocked, got allowed")
	}
}

func TestRateLimiter_IndependentKeys(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	rl.Allow("ip1")
	rl.Allow("ip1")
	// ip1 is now at limit

	if !rl.Allow("ip2") {
		t.Fatal("ip2 should be unaffected by ip1's count")
	}
	if rl.Allow("ip1") {
		t.Fatal("ip1 should be blocked")
	}
}

func TestRateLimiter_ResetsAfterWindow(t *testing.T) {
	window := 50 * time.Millisecond
	rl := NewRateLimiter(1, window)

	if !rl.Allow("ip1") {
		t.Fatal("first request should be allowed")
	}
	if rl.Allow("ip1") {
		t.Fatal("second request should be blocked")
	}

	// Wait for the window to expire.
	time.Sleep(window + 10*time.Millisecond)

	if !rl.Allow("ip1") {
		t.Fatal("first request after window reset should be allowed")
	}
}

func TestRateLimiter_AllowIP(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	ip := net.ParseIP("10.0.0.1")

	if !rl.AllowIP(ip) {
		t.Fatal("first AllowIP should be allowed")
	}
	if rl.AllowIP(ip) {
		t.Fatal("second AllowIP should be blocked")
	}
}

func TestRateLimiter_AllowIP_ZeroLimit(t *testing.T) {
	rl := NewRateLimiter(0, time.Minute)
	ip := net.ParseIP("10.0.0.1")
	for i := 0; i < 50; i++ {
		if !rl.AllowIP(ip) {
			t.Fatalf("AllowIP should always return true when limit=0")
		}
	}
}
