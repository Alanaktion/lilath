package auth

import (
	"bufio"
	"fmt"
	"os"
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

// Verify checks if the given username/password pair is valid.
func (c *Credentials) Verify(username, password string) bool {
	c.mu.RLock()
	hash, ok := c.store[username]
	c.mu.RUnlock()
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
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
func WriteCredentials(path string, entries map[string]string) error {
	f, err := os.CreateTemp("", "lilath-creds-*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()

	w := bufio.NewWriter(f)
	for username, hash := range entries {
		if _, err := fmt.Fprintf(w, "%s:%s\n", username, hash); err != nil {
			f.Close()
			os.Remove(tmpPath)
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	f.Close()

	return os.Rename(tmpPath, path)
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
