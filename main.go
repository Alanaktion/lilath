package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/alanaktion/lilath/internal/auth"
	"github.com/alanaktion/lilath/internal/config"
	"github.com/alanaktion/lilath/internal/server"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	ipCheck, err := auth.NewIPChecker(cfg.IPAllowlist)
	if err != nil {
		log.Fatalf("parsing IP allowlist: %v", err)
	}

	creds, err := auth.LoadCredentials(cfg.CredentialsFile)
	if err != nil {
		log.Fatalf("loading credentials: %v", err)
	}

	sessions := auth.NewSessionStore(cfg.SessionTTL)

	tokens := auth.NewTokenStore()
	if cfg.TokensFile != "" {
		tokens, err = auth.LoadTokens(cfg.TokensFile)
		if err != nil {
			log.Fatalf("loading tokens: %v", err)
		}
	}

	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, tokens)
	if err != nil {
		log.Fatalf("initializing handlers: %v", err)
	}
	srv := server.NewServer(cfg.ListenAddr, h)

	// Reload credentials and tokens on SIGHUP without restarting.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP)
		for range sig {
			log.Println("received SIGHUP, reloading credentials")
			if err := creds.Reload(); err != nil {
				log.Printf("reload error: %v", err)
			}
			if cfg.TokensFile != "" {
				if err := tokens.Reload(cfg.TokensFile); err != nil {
					log.Printf("token reload error: %v", err)
				}
			}
		}
	}()

	log.Printf("lilath listening on %s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
