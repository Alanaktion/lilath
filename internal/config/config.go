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
	SessionTTL      int      `yaml:"session_ttl_minutes"`
	CookieName      string   `yaml:"cookie_name"`
	BaseDomain      string   `yaml:"base_domain"`
	CookieSecure    bool     `yaml:"cookie_secure"`
	// TrustForwardedFor controls whether to trust X-Forwarded-For headers.
	// Enable this when running behind a trusted reverse proxy like Traefik.
	TrustForwardedFor bool `yaml:"trust_forwarded_for"`
	// TrustedProxies is an optional list of IPs/CIDRs belonging to the reverse
	// proxies in front of lilath. When set, forwarding headers are only honoured
	// on connections from these addresses, and any of these addresses appearing
	// in X-Forwarded-For is skipped when determining the client IP. Setting this
	// is strongly recommended whenever trust_forwarded_for is enabled.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// LoginTemplate is an optional path to a custom HTML template file that
	// replaces the built-in login page. Leave empty to use the default.
	LoginTemplate string `yaml:"login_template"`
	// TokensFile is an optional path to a text file containing allowed bearer
	// tokens, one per line. Leave empty to disable Bearer token auth.
	TokensFile string `yaml:"tokens_file"`

	// DefaultUsers is an optional list of usernames allowed to access any
	// service when no service-specific user list header is present. When
	// empty, all authenticated users are permitted (backward-compatible
	// default). Token authentication is never restricted by this list.
	DefaultUsers []string `yaml:"default_users"`
	// UsersHeader is the HTTP request header name that carries a
	// comma-separated list of allowed usernames for the target service.
	// Services set this via a Traefik headers middleware, and the forwardAuth
	// middleware must be configured to forward it.
	// Use the special value "*" to allow all authenticated users regardless of
	// DefaultUsers. Defaults to "X-Lilath-Users".
	UsersHeader string `yaml:"users_header"`
	// UsersHeaderSecret, when set, is a shared secret that must prefix the
	// users header value, separated from the user list by a space:
	//
	//	X-Lilath-Users: <secret> alice,bob
	//
	// lilath cannot otherwise tell a header injected by a proxy middleware from
	// one sent by the client, so without a secret any client can widen its own
	// access by sending the header itself. Values missing or carrying the wrong
	// secret are ignored, falling back to DefaultUsers.
	UsersHeaderSecret string `yaml:"users_header_secret"`

	// Rate limiting — per IP, fixed-window counter.
	// Set a limit to 0 to disable that limiter.

	// RateLimitRequests is the maximum number of requests to GET /auth allowed
	// per IP per window. 0 disables the limiter.
	RateLimitRequests int `yaml:"rate_limit_requests"`
	// RateLimitLoginRequests is the maximum number of POST /login attempts
	// allowed per IP per window. 0 disables the limiter.
	RateLimitLoginRequests int `yaml:"rate_limit_login_requests"`
	// RateLimitWindowSeconds is the size of the rate-limit window in seconds.
	RateLimitWindowSeconds int `yaml:"rate_limit_window_seconds"`
	// RateLimitAllowlist is an optional list of IPs/CIDRs exempt from all rate
	// limiting. IPs already in IPAllowlist are also exempt.
	RateLimitAllowlist []string `yaml:"rate_limit_allowlist"`
}

func defaults() *Config {
	return &Config{
		ListenAddr:             ":8080",
		CredentialsFile:        "users.txt",
		SessionTTL:             60,
		CookieName:             "lilath_session",
		CookieSecure:           true,
		TrustForwardedFor:      true,
		RateLimitRequests:      300,
		RateLimitLoginRequests: 10,
		RateLimitWindowSeconds: 60,
	}
}

func Load(path string) (*Config, error) {
	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			applyEnv(cfg)
			normalize(cfg)
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	applyEnv(cfg)
	normalize(cfg)
	return cfg, nil
}

// normalize repairs values that are out of range. A non-positive session TTL
// would expire every session the instant it was created, and a non-positive
// rate-limit window would make the window meaningless, so both fall back to
// their defaults rather than silently breaking authentication.
func normalize(cfg *Config) {
	d := defaults()
	if cfg.SessionTTL <= 0 {
		fmt.Fprintf(os.Stderr, "lilath: session_ttl_minutes must be positive, using %d\n", d.SessionTTL)
		cfg.SessionTTL = d.SessionTTL
	}
	if cfg.RateLimitWindowSeconds <= 0 {
		fmt.Fprintf(os.Stderr, "lilath: rate_limit_window_seconds must be positive, using %d\n", d.RateLimitWindowSeconds)
		cfg.RateLimitWindowSeconds = d.RateLimitWindowSeconds
	}
	if cfg.RateLimitRequests < 0 {
		cfg.RateLimitRequests = 0
	}
	if cfg.RateLimitLoginRequests < 0 {
		cfg.RateLimitLoginRequests = 0
	}
}

// applyEnv overlays LILATH_* environment variables on top of cfg.
// Environment variables take precedence over values from the config file.
//
// Supported variables:
//
//	LILATH_LISTEN_ADDR              — e.g. ":8080"
//	LILATH_CREDENTIALS_FILE         — e.g. "/data/users.txt"
//	LILATH_IP_ALLOWLIST             — comma-separated IPs/CIDRs, e.g. "127.0.0.1,10.0.0.0/8"
//	LILATH_TRUSTED_PROXIES          — comma-separated IPs/CIDRs of the proxies in front of lilath
//	LILATH_SESSION_TTL_MINUTES      — integer, e.g. "60"
//	LILATH_COOKIE_NAME              — e.g. "lilath_session"
//	LILATH_BASE_DOMAIN              — e.g. "example.com"
//	LILATH_COOKIE_SECURE            — "true"/"1"/"yes" or "false"/"0"/"no"
//	LILATH_TRUST_FORWARDED_FOR      — "true"/"1"/"yes" or "false"/"0"/"no"
//	LILATH_LOGIN_TEMPLATE           — e.g. "/data/login.html"
//	LILATH_TOKENS_FILE              — e.g. "/data/tokens.txt"
//	LILATH_DEFAULT_USERS            — comma-separated usernames, e.g. "alice,bob"
//	LILATH_USERS_HEADER             — header name, e.g. "X-Lilath-Users"
//	LILATH_USERS_HEADER_SECRET      — shared secret required to prefix the users header value
//	LILATH_RATE_LIMIT_REQUESTS      — integer, max GET /auth requests per window per IP (0 = disabled)
//	LILATH_RATE_LIMIT_LOGIN         — integer, max POST /login attempts per window per IP (0 = disabled)
//	LILATH_RATE_LIMIT_WINDOW        — integer seconds, rate-limit window size
//	LILATH_RATE_LIMIT_ALLOWLIST     — comma-separated IPs/CIDRs exempt from rate limiting
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
	if v := os.Getenv("LILATH_TRUSTED_PROXIES"); v != "" {
		cfg.TrustedProxies = splitList(v)
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
	if v := os.Getenv("LILATH_TOKENS_FILE"); v != "" {
		cfg.TokensFile = v
	}
	if v := os.Getenv("LILATH_DEFAULT_USERS"); v != "" {
		cfg.DefaultUsers = splitList(v)
	}
	if v := os.Getenv("LILATH_USERS_HEADER"); v != "" {
		cfg.UsersHeader = v
	}
	if v := os.Getenv("LILATH_USERS_HEADER_SECRET"); v != "" {
		cfg.UsersHeaderSecret = v
	}
	if v := os.Getenv("LILATH_RATE_LIMIT_REQUESTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimitRequests = n
		} else {
			fmt.Fprintf(os.Stderr, "lilath: invalid LILATH_RATE_LIMIT_REQUESTS %q, using default\n", v)
		}
	}
	if v := os.Getenv("LILATH_RATE_LIMIT_LOGIN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimitLoginRequests = n
		} else {
			fmt.Fprintf(os.Stderr, "lilath: invalid LILATH_RATE_LIMIT_LOGIN %q, using default\n", v)
		}
	}
	if v := os.Getenv("LILATH_RATE_LIMIT_WINDOW"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimitWindowSeconds = n
		} else {
			fmt.Fprintf(os.Stderr, "lilath: invalid LILATH_RATE_LIMIT_WINDOW %q, using default\n", v)
		}
	}
	if v := os.Getenv("LILATH_RATE_LIMIT_ALLOWLIST"); v != "" {
		cfg.RateLimitAllowlist = splitList(v)
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
