package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr      string   `yaml:"listen_addr"`
	CredentialsFile string   `yaml:"credentials_file"`
	IPAllowlist     []string `yaml:"ip_allowlist"`
	SessionSecret   string   `yaml:"session_secret"`
	SessionTTL      int      `yaml:"session_ttl_minutes"`
	CookieName      string   `yaml:"cookie_name"`
	CookieSecure    bool     `yaml:"cookie_secure"`
	// TrustForwardedFor controls whether to trust X-Forwarded-For headers.
	// Enable this when running behind a trusted reverse proxy like Traefik.
	TrustForwardedFor bool `yaml:"trust_forwarded_for"`
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
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return cfg, nil
}
