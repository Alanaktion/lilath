package auth_test

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/alanaktion/lilath/internal/auth"
)

// TestWriteCredentials_RejectsInjectedUsername covers credential-file injection:
// the file format is line-based, so a username containing a newline (or the
// field separator) could otherwise smuggle an extra account — with an
// attacker-chosen hash — into the file.
func TestWriteCredentials_RejectsInjectedUsername(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")

	for _, username := range []string{"bob\nadmin", "bob:admin", "bob\rx"} {
		err := auth.WriteCredentials(path, map[string]string{username: "$2a$10$hash"})
		if err == nil {
			t.Errorf("WriteCredentials(%q) = nil, want an error", username)
		}
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("credentials file should not have been written, stat err = %v", err)
	}
}

func TestWriteCredentials_ModeAndLocation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.txt")

	if err := auth.WriteCredentials(path, map[string]string{"alice": "$2a$10$hash"}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions = %o, want 600", perm)
	}

	// The temp file must be created alongside the target (same filesystem) and
	// must not survive the write.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected only users.txt in the directory, got %d entries", len(entries))
	}
}

func TestCredentials_Exists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")
	hash, err := auth.HashPassword("pw")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{"alice": hash}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}
	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	if !creds.Exists("alice") {
		t.Error("Exists(alice) = false, want true")
	}
	if creds.Exists("bob") {
		t.Error("Exists(bob) = true, want false")
	}
	if creds.Len() != 1 {
		t.Errorf("Len = %d, want 1", creds.Len())
	}

	// Removing the user and reloading must be reflected immediately.
	if err := auth.WriteCredentials(path, map[string]string{}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}
	if err := creds.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if creds.Exists("alice") {
		t.Error("Exists(alice) = true after removal, want false")
	}
}

// TestRateLimiter_PeekAndRecord verifies that Peek does not consume budget,
// which is what lets failed Basic auth attempts be charged to the login limiter
// while successful ones pass through freely.
func TestRateLimiter_PeekAndRecord(t *testing.T) {
	rl := auth.NewRateLimiter(2, time.Minute)

	for i := 0; i < 5; i++ {
		if !rl.Peek("k") {
			t.Fatalf("Peek %d = false, want true (Peek must not consume budget)", i)
		}
	}

	rl.Record("k")
	if !rl.Peek("k") {
		t.Fatal("Peek after 1 of 2 = false, want true")
	}
	rl.Record("k")
	if rl.Peek("k") {
		t.Fatal("Peek after 2 of 2 = true, want false")
	}
}

func TestRateLimiter_NegativeLimitDisables(t *testing.T) {
	rl := auth.NewRateLimiter(-1, time.Minute)
	for i := 0; i < 5; i++ {
		if !rl.Allow("k") {
			t.Fatalf("request %d denied: a negative limit must disable the limiter, not deny everything", i)
		}
	}
}

// TestRateLimiterKey_IPv6GroupedByPrefix covers the brute-force bypass available
// to anyone with an IPv6 allocation: a fresh address per request would each get
// its own bucket.
func TestRateLimiterKey_IPv6GroupedByPrefix(t *testing.T) {
	a := auth.Key(net.ParseIP("2001:db8::1"))
	b := auth.Key(net.ParseIP("2001:db8::dead:beef"))
	if a != b {
		t.Errorf("addresses in the same /64 got different keys: %q vs %q", a, b)
	}

	c := auth.Key(net.ParseIP("2001:db8:1::1"))
	if a == c {
		t.Errorf("addresses in different /64s share key %q", a)
	}

	if got, want := auth.Key(net.ParseIP("203.0.113.9")), "203.0.113.9"; got != want {
		t.Errorf("Key(IPv4) = %q, want %q", got, want)
	}
}

// TestSessionStore_ConcurrentGetRefresh exercises the Get/Refresh pair; it fails
// under -race if Get hands out the stored Session for callers to read while
// Refresh is writing to it.
func TestSessionStore_ConcurrentGetRefresh(t *testing.T) {
	store := auth.NewSessionStore(60)
	id, err := store.Create("alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if sess := store.Get(id); sess != nil {
					_ = sess.ExpiresAt
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				store.Refresh(id)
			}
		}()
	}
	wg.Wait()
}
