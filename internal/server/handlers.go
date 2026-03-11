package server

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/alanaktion/lilath/internal/auth"
	"github.com/alanaktion/lilath/internal/config"
)

//go:embed templates
var templateFS embed.FS

var defaultLoginTmpl = template.Must(
	template.ParseFS(templateFS, "templates/login.html"),
)

// Handlers bundles all HTTP handler state.
type Handlers struct {
	cfg       *config.Config
	creds     *auth.Credentials
	sessions  *auth.SessionStore
	ipCheck   *auth.IPChecker
	loginTmpl *template.Template
}

func NewHandlers(
	cfg *config.Config,
	creds *auth.Credentials,
	sessions *auth.SessionStore,
	ipCheck *auth.IPChecker,
) (*Handlers, error) {
	tmpl := defaultLoginTmpl
	if cfg.LoginTemplate != "" {
		t, err := template.ParseFiles(cfg.LoginTemplate)
		if err != nil {
			return nil, fmt.Errorf("loading login template %q: %w", cfg.LoginTemplate, err)
		}
		tmpl = t
	}
	return &Handlers{cfg: cfg, creds: creds, sessions: sessions, ipCheck: ipCheck, loginTmpl: tmpl}, nil
}

// ForwardAuth is the Traefik forwardAuth endpoint.
// Returns 200 when the request is authenticated, 302 to /login otherwise.
func (h *Handlers) ForwardAuth(w http.ResponseWriter, r *http.Request) {
	// 1. Check IP allowlist.
	if !h.ipCheck.IsEmpty() {
		clientIP := auth.ClientIP(r, h.cfg.TrustForwardedFor)
		if clientIP != nil && h.ipCheck.Allow(clientIP) {
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// 2. Check session cookie.
	cookie, err := r.Cookie(h.cfg.CookieName)
	if err == nil && cookie.Value != "" {
		sess := h.sessions.Get(cookie.Value)
		if sess != nil {
			h.sessions.Refresh(cookie.Value)
			w.Header().Set("X-Auth-User", sess.Username)
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// Not authenticated — redirect to login, encoding the original URI.
	originalURI := r.Header.Get("X-Forwarded-Uri")
	if originalURI == "" {
		originalURI = "/"
	}

	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := r.Header.Get("X-Forwarded-Host")

	var loginURL string
	if h.cfg.BaseDomain != "" {
		rd := originalURI
		if host != "" && strings.HasPrefix(originalURI, "/") {
			rd = proto + "://" + host + originalURI
		}
		loginURL = proto + "://" + normalizeBaseDomain(h.cfg.BaseDomain) + "/login?rd=" + url.QueryEscape(rd)
	} else if host != "" {
		// Use the forwarded host/proto for the redirect when available.
		loginURL = proto + "://" + host + "/login?rd=" + url.QueryEscape(originalURI)
	} else {
		// Fall back to a relative redirect when no forwarded host is available.
		loginURL = "/login?rd=" + url.QueryEscape(originalURI)
	}

	http.Redirect(w, r, loginURL, http.StatusFound)
}

type loginData struct {
	Error       string
	RedirectURL string
}

// LoginPage renders the login form.
func (h *Handlers) LoginPage(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.Query().Get("rd")
	if rd == "" {
		rd = "/"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.loginTmpl.Execute(w, loginData{RedirectURL: rd}); err != nil {
		log.Printf("template error: %v", err)
	}
}

// LoginSubmit handles credential submission.
func (h *Handlers) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	rd := r.FormValue("rd")
	if rd == "" {
		rd = "/"
	}

	if !h.creds.Verify(username, password) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		if err := h.loginTmpl.Execute(w, loginData{Error: "Invalid username or password.", RedirectURL: rd}); err != nil {
			log.Printf("template error: %v", err)
		}
		return
	}

	sessionID, err := h.sessions.Create(username)
	if err != nil {
		log.Printf("failed to create session: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.CookieName,
		Value:    sessionID,
		Path:     "/",
		Domain:   cookieDomain(h.cfg.BaseDomain),
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, rd, http.StatusFound)
}

// Logout deletes the session and clears the cookie.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(h.cfg.CookieName); err == nil {
		h.sessions.Delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   cookieDomain(h.cfg.BaseDomain),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func normalizeBaseDomain(base string) string {
	return strings.TrimPrefix(strings.TrimSpace(base), ".")
}

func cookieDomain(base string) string {
	return normalizeBaseDomain(base)
}
