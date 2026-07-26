package auth

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// Credentials holds a thread-safe map of username to bcrypt hash loaded from
// a flat text file with the format:
//
//	username:$2a$10$...
type Credentials struct {
	mu    sync.RWMutex
	store map[string]string
	path  string
}

// LoadCredentials reads the credentials file from path.
// Lines beginning with '#' and empty lines are ignored.
func LoadCredentials(path string) (*Credentials, error) {
	c := &Credentials{path: path}
	if err := c.reload(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Credentials) reload() error {
	f, err := os.Open(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			c.mu.Lock()
			c.store = make(map[string]string)
			c.mu.Unlock()
			return nil
		}
		return fmt.Errorf("opening credentials file: %w", err)
	}
	defer f.Close()

	store := make(map[string]string)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("credentials file line %d: expected 'username:hash' format", lineNum)
		}
		store[parts[0]] = parts[1]
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading credentials file: %w", err)
	}

	c.mu.Lock()
	c.store = store
	c.mu.Unlock()
	return nil
}

// Reload re-reads the credentials file from disk.
func (c *Credentials) Reload() error {
	return c.reload()
}

// dummyHash is a valid bcrypt hash at DefaultCost of a value nobody knows. It
// is compared against when the supplied username does not exist so that the
// cost — and therefore the response time — of an unknown username matches that
// of a known one. Without it, "user exists" leaks through response timing
// (a hash comparison takes ~100ms; a map miss is instant) and valid usernames
// can be enumerated.
const dummyHash = "$2a$10$oDu9NWtI7nAi6c0nqQfNvOVXTb3M6jq1llyEHZBbQjuFpRl/znc0y"

// Verify checks if the given username/password pair is valid.
func (c *Credentials) Verify(username, password string) bool {
	c.mu.RLock()
	hash, ok := c.store[username]
	c.mu.RUnlock()
	if !ok {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// Exists reports whether a username is present in the credentials store.
// It performs no password check.
func (c *Credentials) Exists(username string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.store[username]
	return ok
}

// Len returns the number of loaded credentials.
func (c *Credentials) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.store)
}

// HashPassword generates a bcrypt hash for the given password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// WriteCredentials writes the provided credentials map back to a file,
// preserving the username:hash format. Existing comments are not preserved.
// The temp file is created in the destination directory, both so the rename is
// atomic (a rename across filesystems fails with EXDEV) and so password hashes
// are never written to a shared location such as /tmp.
func WriteCredentials(path string, entries map[string]string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".lilath-creds-*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()

	fail := func(err error) error {
		f.Close()
		os.Remove(tmpPath)
		return err
	}

	// os.CreateTemp already uses 0600, but be explicit: this file holds
	// password hashes.
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}

	w := bufio.NewWriter(f)
	for username, hash := range entries {
		if strings.ContainsAny(username, ":\r\n") {
			return fail(fmt.Errorf("invalid username %q: must not contain ':' or a newline", username))
		}
		if strings.ContainsAny(hash, "\r\n") {
			return fail(fmt.Errorf("invalid hash for user %q: must not contain a newline", username))
		}
		if _, err := fmt.Fprintf(w, "%s:%s\n", username, hash); err != nil {
			return fail(err)
		}
	}
	if err := w.Flush(); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// ReadAll returns a copy of all username→hash entries.
func (c *Credentials) ReadAll() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]string, len(c.store))
	for k, v := range c.store {
		out[k] = v
	}
	return out
}
