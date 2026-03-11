package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr: got %q, want %q", cfg.ListenAddr, ":8080")
	}
	if cfg.CredentialsFile != "users.txt" {
		t.Errorf("CredentialsFile: got %q, want %q", cfg.CredentialsFile, "users.txt")
	}
	if cfg.SessionTTL != 60 {
		t.Errorf("SessionTTL: got %d, want 60", cfg.SessionTTL)
	}
	if cfg.CookieName != "lilath_session" {
		t.Errorf("CookieName: got %q, want %q", cfg.CookieName, "lilath_session")
	}
	if cfg.BaseDomain != "" {
		t.Errorf("BaseDomain: got %q, want empty", cfg.BaseDomain)
	}
	if !cfg.CookieSecure {
		t.Error("CookieSecure: got false, want true")
	}
	if !cfg.TrustForwardedFor {
		t.Error("TrustForwardedFor: got false, want true")
	}
}

func TestLoad_EnvOverridesDefaults(t *testing.T) {
	t.Setenv("LILATH_LISTEN_ADDR", ":9090")
	t.Setenv("LILATH_CREDENTIALS_FILE", "/custom/users.txt")
	t.Setenv("LILATH_SESSION_SECRET", "mysecret")
	t.Setenv("LILATH_SESSION_TTL_MINUTES", "120")
	t.Setenv("LILATH_COOKIE_NAME", "my_cookie")
	t.Setenv("LILATH_BASE_DOMAIN", "example.com")
	t.Setenv("LILATH_COOKIE_SECURE", "false")
	t.Setenv("LILATH_TRUST_FORWARDED_FOR", "false")
	t.Setenv("LILATH_IP_ALLOWLIST", "127.0.0.1, 10.0.0.0/8")

	cfg, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr: got %q, want %q", cfg.ListenAddr, ":9090")
	}
	if cfg.CredentialsFile != "/custom/users.txt" {
		t.Errorf("CredentialsFile: got %q, want %q", cfg.CredentialsFile, "/custom/users.txt")
	}
	if cfg.SessionSecret != "mysecret" {
		t.Errorf("SessionSecret: got %q, want %q", cfg.SessionSecret, "mysecret")
	}
	if cfg.SessionTTL != 120 {
		t.Errorf("SessionTTL: got %d, want 120", cfg.SessionTTL)
	}
	if cfg.CookieName != "my_cookie" {
		t.Errorf("CookieName: got %q, want %q", cfg.CookieName, "my_cookie")
	}
	if cfg.BaseDomain != "example.com" {
		t.Errorf("BaseDomain: got %q, want %q", cfg.BaseDomain, "example.com")
	}
	if cfg.CookieSecure {
		t.Error("CookieSecure: got true, want false")
	}
	if cfg.TrustForwardedFor {
		t.Error("TrustForwardedFor: got true, want false")
	}
	if len(cfg.IPAllowlist) != 2 || cfg.IPAllowlist[0] != "127.0.0.1" || cfg.IPAllowlist[1] != "10.0.0.0/8" {
		t.Errorf("IPAllowlist: got %v, want [127.0.0.1 10.0.0.0/8]", cfg.IPAllowlist)
	}
}

func TestLoad_EnvOverridesFile(t *testing.T) {
	// Write a config file with specific values.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(cfgPath, []byte(`listen_addr: ":7070"
credentials_file: /file/users.txt
session_ttl_minutes: 30
`), 0600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Env var should override the file value.
	t.Setenv("LILATH_LISTEN_ADDR", ":9999")

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.ListenAddr != ":9999" {
		t.Errorf("ListenAddr: got %q, want %q", cfg.ListenAddr, ":9999")
	}
	// File value should still apply where no env var is set.
	if cfg.CredentialsFile != "/file/users.txt" {
		t.Errorf("CredentialsFile: got %q, want %q", cfg.CredentialsFile, "/file/users.txt")
	}
	if cfg.SessionTTL != 30 {
		t.Errorf("SessionTTL: got %d, want 30", cfg.SessionTTL)
	}
}

func TestLoad_BoolEnvVars(t *testing.T) {
	tests := []struct {
		val  string
		want bool
	}{
		{"true", true},
		{"1", true},
		{"yes", true},
		{"on", true},
		{"TRUE", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"off", false},
	}

	for _, tc := range tests {
		t.Run(tc.val, func(t *testing.T) {
			t.Setenv("LILATH_COOKIE_SECURE", tc.val)
			t.Setenv("LILATH_TRUST_FORWARDED_FOR", tc.val)

			cfg := defaults()
			applyEnv(cfg)

			if cfg.CookieSecure != tc.want {
				t.Errorf("CookieSecure(%q): got %v, want %v", tc.val, cfg.CookieSecure, tc.want)
			}
			if cfg.TrustForwardedFor != tc.want {
				t.Errorf("TrustForwardedFor(%q): got %v, want %v", tc.val, cfg.TrustForwardedFor, tc.want)
			}
		})
	}
}

func TestLoad_LoginTemplateEnv(t *testing.T) {
	t.Setenv("LILATH_LOGIN_TEMPLATE", "/data/custom-login.html")

	cfg := defaults()
	applyEnv(cfg)

	if cfg.LoginTemplate != "/data/custom-login.html" {
		t.Errorf("LoginTemplate: got %q, want %q", cfg.LoginTemplate, "/data/custom-login.html")
	}
}

func TestLoad_LoginTemplateYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(cfgPath, []byte("login_template: /data/custom-login.html\n"), 0600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.LoginTemplate != "/data/custom-login.html" {
		t.Errorf("LoginTemplate: got %q, want %q", cfg.LoginTemplate, "/data/custom-login.html")
	}
}

func TestLoad_IPAllowlistEnv(t *testing.T) {
	tests := []struct {
		env  string
		want []string
	}{
		{"127.0.0.1", []string{"127.0.0.1"}},
		{"127.0.0.1,::1", []string{"127.0.0.1", "::1"}},
		{"127.0.0.1, 10.0.0.0/8, ::1", []string{"127.0.0.1", "10.0.0.0/8", "::1"}},
	}

	for _, tc := range tests {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("LILATH_IP_ALLOWLIST", tc.env)

			cfg := defaults()
			applyEnv(cfg)

			if len(cfg.IPAllowlist) != len(tc.want) {
				t.Fatalf("IPAllowlist len: got %d, want %d", len(cfg.IPAllowlist), len(tc.want))
			}
			for i, v := range tc.want {
				if cfg.IPAllowlist[i] != v {
					t.Errorf("IPAllowlist[%d]: got %q, want %q", i, cfg.IPAllowlist[i], v)
				}
			}
		})
	}
}
