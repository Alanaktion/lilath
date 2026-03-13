package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTokensFile(t *testing.T, dir string, content string) string {
	t.Helper()
	path := filepath.Join(dir, "tokens.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestNewTokenStore_Empty(t *testing.T) {
	ts := NewTokenStore()
	if !ts.IsEmpty() {
		t.Fatal("expected empty store")
	}
	if ts.Allow("anything") {
		t.Fatal("expected Allow to return false on empty store")
	}
}

func TestLoadTokens_Basic(t *testing.T) {
	dir := t.TempDir()
	path := writeTokensFile(t, dir, "token-a\ntoken-b\ntoken-c\n")

	ts, err := LoadTokens(path)
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}
	if ts.IsEmpty() {
		t.Fatal("expected non-empty store")
	}

	for _, tok := range []string{"token-a", "token-b", "token-c"} {
		if !ts.Allow(tok) {
			t.Errorf("expected Allow(%q) = true", tok)
		}
	}
	if ts.Allow("not-a-token") {
		t.Error("expected Allow(\"not-a-token\") = false")
	}
}

func TestLoadTokens_IgnoresCommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	content := `# This is a comment
token-1

# Another comment
   
token-2
`
	path := writeTokensFile(t, dir, content)

	ts, err := LoadTokens(path)
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}

	if !ts.Allow("token-1") {
		t.Error("expected Allow(\"token-1\") = true")
	}
	if !ts.Allow("token-2") {
		t.Error("expected Allow(\"token-2\") = true")
	}
	if ts.Allow("# This is a comment") {
		t.Error("expected comment line not to be a valid token")
	}
}

func TestLoadTokens_NonExistentFile(t *testing.T) {
	ts, err := LoadTokens(filepath.Join(t.TempDir(), "nonexistent.txt"))
	if err != nil {
		t.Fatalf("LoadTokens with nonexistent file: expected no error, got %v", err)
	}
	if !ts.IsEmpty() {
		t.Fatal("expected empty store for nonexistent file")
	}
}

func TestTokenStore_Reload(t *testing.T) {
	dir := t.TempDir()
	path := writeTokensFile(t, dir, "original-token\n")

	ts, err := LoadTokens(path)
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}

	if !ts.Allow("original-token") {
		t.Fatal("expected original-token before reload")
	}

	// Overwrite the file with a new token.
	if err := os.WriteFile(path, []byte("new-token\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := ts.Reload(path); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if ts.Allow("original-token") {
		t.Error("expected original-token to be absent after reload")
	}
	if !ts.Allow("new-token") {
		t.Error("expected new-token after reload")
	}
}

func TestTokenStore_IsEmpty(t *testing.T) {
	dir := t.TempDir()

	// File with only comments.
	path := writeTokensFile(t, dir, "# just a comment\n\n")
	ts, err := LoadTokens(path)
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}
	if !ts.IsEmpty() {
		t.Fatal("expected IsEmpty = true for comment-only file")
	}

	// Now add a token.
	if err := os.WriteFile(path, []byte("a-token\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ts.Reload(path); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if ts.IsEmpty() {
		t.Fatal("expected IsEmpty = false after adding a token")
	}
}
