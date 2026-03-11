package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr      string   `yaml:"listen_addr"`
	CredentialsFile string   `yaml:"credentials_file"`
	IPAllowlist     []string `yaml:"ip_allowlist"`
	SessionSecret   string   `yaml:"session_secret"`
	SessionTTL      int      `yaml:"session_ttl_minutes"`
	CookieName      string   `yaml:"cookie_name"`
	BaseDomain      string   `yaml:"base_domain"`
	CookieSecure    bool     `yaml:"cookie_secure"`
	// TrustForwardedFor controls whether to trust X-Forwarded-For headers.
	// Enable this when running behind a trusted reverse proxy like Traefik.
	TrustForwardedFor bool `yaml:"trust_forwarded_for"`
	// LoginTemplate is an optional path to a custom HTML template file that
	// replaces the built-in login page. Leave empty to use the default.
	LoginTemplate string `yaml:"login_template"`
}

func defaults() *Config {
	return &Config{
		ListenAddr:        ":8080",
		CredentialsFile:   "users.txt",
		SessionTTL:        60,
		CookieName:        "lilath_session",
		CookieSecure:      true,
		TrustForwardedFor: true,
	}
}

func Load(path string) (*Config, error) {
	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			applyEnv(cfg)
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	applyEnv(cfg)
	return cfg, nil
}

// applyEnv overlays LILATH_* environment variables on top of cfg.
// Environment variables take precedence over values from the config file.
//
// Supported variables:
//
//	LILATH_LISTEN_ADDR         — e.g. ":8080"
//	LILATH_CREDENTIALS_FILE    — e.g. "/data/users.txt"
//	LILATH_IP_ALLOWLIST        — comma-separated IPs/CIDRs, e.g. "127.0.0.1,10.0.0.0/8"
//	LILATH_SESSION_SECRET      — arbitrary string
//	LILATH_SESSION_TTL_MINUTES — integer, e.g. "60"
//	LILATH_COOKIE_NAME         — e.g. "lilath_session"
//	LILATH_BASE_DOMAIN         — e.g. "example.com"
//	LILATH_COOKIE_SECURE       — "true"/"1"/"yes" or "false"/"0"/"no"
//	LILATH_TRUST_FORWARDED_FOR — "true"/"1"/"yes" or "false"/"0"/"no"
//	LILATH_LOGIN_TEMPLATE      — e.g. "/data/login.html"
func applyEnv(cfg *Config) {
	if v := os.Getenv("LILATH_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("LILATH_CREDENTIALS_FILE"); v != "" {
		cfg.CredentialsFile = v
	}
	if v := os.Getenv("LILATH_IP_ALLOWLIST"); v != "" {
		cfg.IPAllowlist = splitList(v)
	}
	if v := os.Getenv("LILATH_SESSION_SECRET"); v != "" {
		cfg.SessionSecret = v
	}
	if v := os.Getenv("LILATH_SESSION_TTL_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.SessionTTL = n
		} else {
			fmt.Fprintf(os.Stderr, "lilath: invalid LILATH_SESSION_TTL_MINUTES %q, using default\n", v)
		}
	}
	if v := os.Getenv("LILATH_COOKIE_NAME"); v != "" {
		cfg.CookieName = v
	}
	if v := os.Getenv("LILATH_BASE_DOMAIN"); v != "" {
		cfg.BaseDomain = v
	}
	if v, ok := os.LookupEnv("LILATH_COOKIE_SECURE"); ok && v != "" {
		cfg.CookieSecure = parseBool(v)
	}
	if v, ok := os.LookupEnv("LILATH_TRUST_FORWARDED_FOR"); ok && v != "" {
		cfg.TrustForwardedFor = parseBool(v)
	}
	if v := os.Getenv("LILATH_LOGIN_TEMPLATE"); v != "" {
		cfg.LoginTemplate = v
	}
}

// splitList splits a comma-separated string, trimming whitespace from each entry.
func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// parseBool parses common boolean string representations.
func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return false
	}
}
