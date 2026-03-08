package auth_test

import (
	"path/filepath"
	"testing"

	"github.com/alanaktion/lilath/internal/auth"
)

func TestHashPassword(t *testing.T) {
	hash, err := auth.HashPassword("password123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if hash == "password123" {
		t.Fatal("hash should not equal the plaintext password")
	}
}

func TestLoadCredentials_NonExistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.txt")
	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials on non-existent file: %v", err)
	}
	if entries := creds.ReadAll(); len(entries) != 0 {
		t.Fatalf("expected empty credentials, got %d entries", len(entries))
	}
}

func TestWriteAndLoadCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")

	hash, err := auth.HashPassword("testpass")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	entries := map[string]string{"alice": hash}
	if err := auth.WriteCredentials(path, entries); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}

	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	loaded := creds.ReadAll()
	if len(loaded) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(loaded))
	}
	if loaded["alice"] != hash {
		t.Fatal("loaded hash does not match written hash")
	}
}

func TestVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")

	hash, err := auth.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{"bob": hash}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}

	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	if !creds.Verify("bob", "secret") {
		t.Fatal("expected Verify to return true for valid credentials")
	}
	if creds.Verify("bob", "wrongpassword") {
		t.Fatal("expected Verify to return false for wrong password")
	}
	if creds.Verify("unknown", "secret") {
		t.Fatal("expected Verify to return false for unknown user")
	}
}

// TestAddUser simulates the add-user flow: load an empty store, add a user,
// write it back, reload, and verify credentials work.
func TestAddUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")

	// Load empty store (file does not exist yet).
	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	entries := creds.ReadAll()

	// Add the user.
	hash, err := auth.HashPassword("mypassword")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	entries["carol"] = hash

	if err := auth.WriteCredentials(path, entries); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}

	// Reload and verify.
	creds2, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials after add: %v", err)
	}
	if !creds2.Verify("carol", "mypassword") {
		t.Fatal("expected Verify to succeed for newly-added user")
	}
}

// TestUpdateUser simulates updating an existing user's password.
func TestUpdateUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")

	hash1, err := auth.HashPassword("oldpass")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{"dave": hash1}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}

	// Update password.
	hash2, err := auth.HashPassword("newpass")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{"dave": hash2}); err != nil {
		t.Fatalf("WriteCredentials (update): %v", err)
	}

	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if creds.Verify("dave", "oldpass") {
		t.Fatal("expected old password to be invalid after update")
	}
	if !creds.Verify("dave", "newpass") {
		t.Fatal("expected new password to be valid after update")
	}
}

// TestDeleteUser simulates deleting a user from the credentials file.
func TestDeleteUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")

	hash, err := auth.HashPassword("pass")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	entries := map[string]string{"eve": hash, "frank": hash}
	if err := auth.WriteCredentials(path, entries); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}

	// Delete "eve".
	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	remaining := creds.ReadAll()
	delete(remaining, "eve")
	if err := auth.WriteCredentials(path, remaining); err != nil {
		t.Fatalf("WriteCredentials after delete: %v", err)
	}

	// Reload and verify.
	creds2, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials after delete: %v", err)
	}
	loaded := creds2.ReadAll()
	if _, ok := loaded["eve"]; ok {
		t.Fatal("expected 'eve' to be absent after deletion")
	}
	if _, ok := loaded["frank"]; !ok {
		t.Fatal("expected 'frank' to still be present")
	}
}

// TestReload verifies that Reload picks up changes written after the initial load.
func TestReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")

	hash, err := auth.HashPassword("pass1")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{"grace": hash}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}

	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if !creds.Verify("grace", "pass1") {
		t.Fatal("initial verify failed")
	}

	// Overwrite with a new password.
	hash2, err := auth.HashPassword("pass2")
	if err != nil {
		t.Fatalf("HashPassword (2): %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{"grace": hash2}); err != nil {
		t.Fatalf("WriteCredentials (2): %v", err)
	}

	if err := creds.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if creds.Verify("grace", "pass1") {
		t.Fatal("expected old password to be invalid after reload")
	}
	if !creds.Verify("grace", "pass2") {
		t.Fatal("expected new password to be valid after reload")
	}
}
