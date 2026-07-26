package server

import (
	"log"
	"net/http"
	"time"
)

// loggingMiddleware logs each request's method, path, status code, and duration.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		// %q on the URI: it is attacker-controlled and goes into a log line.
		log.Printf("%s %q %d %s", r.Method, r.RequestURI, rw.status, time.Since(start))
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

// NewServer builds and returns the HTTP server.
func NewServer(addr string, h *Handlers) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// Registered for every method, not just GET: Traefik issues a GET by default
	// but can be configured to preserve the original request method, and a 405
	// from the mux would then deny every non-GET request to protected services.
	mux.HandleFunc("/auth", h.ForwardAuth)
	mux.HandleFunc("GET /login", h.LoginPage)
	mux.HandleFunc("POST /login", h.LoginSubmit)
	mux.HandleFunc("GET /logout", h.Logout)
	mux.HandleFunc("POST /logout", h.Logout)

	return &http.Server{
		Addr:              addr,
		Handler:           loggingMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}
