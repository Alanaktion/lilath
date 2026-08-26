package server

import (
	"crypto/subtle"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alanaktion/lilath/internal/auth"
	"github.com/alanaktion/lilath/internal/config"
)

//go:embed templates
var templateFS embed.FS

var defaultLoginTmpl = template.Must(
	template.ParseFS(templateFS, "templates/login.html"),
)

// maxLoginBodyBytes caps the size of a POST /login body. The form carries a
// username, a password and a redirect target; anything larger is abuse.
const maxLoginBodyBytes = 64 << 10

// Handlers bundles all HTTP handler state.
type Handlers struct {
	cfg              *config.Config
	creds            *auth.Credentials
	sessions         *auth.SessionStore
	ipCheck          *auth.IPChecker
	tokens           *auth.TokenStore
	loginTmpl        *template.Template
	rateLimiter      *auth.RateLimiter
	loginRateLimiter *auth.RateLimiter
	rlAllowlist      *auth.IPChecker
	trustedProxies   *auth.IPChecker
	customTmpl       bool
}

func NewHandlers(
	cfg *config.Config,
	creds *auth.Credentials,
	sessions *auth.SessionStore,
	ipCheck *auth.IPChecker,
	tokens *auth.TokenStore,
) (*Handlers, error) {
	tmpl := defaultLoginTmpl
	customTmpl := cfg.LoginTemplate != ""
	if cfg.LoginTemplate != "" {
		t, err := template.ParseFiles(cfg.LoginTemplate)
		if err != nil {
			return nil, fmt.Errorf("loading login template %q: %w", cfg.LoginTemplate, err)
		}
		tmpl = t
	}

	rlAllowlist, err := auth.NewIPChecker(cfg.RateLimitAllowlist)
	if err != nil {
		return nil, fmt.Errorf("parsing rate limit allowlist: %w", err)
	}

	trustedProxies, err := auth.NewIPChecker(cfg.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("parsing trusted proxies: %w", err)
	}

	window := time.Duration(cfg.RateLimitWindowSeconds) * time.Second
	if window <= 0 {
		window = time.Minute
	}

	return &Handlers{
		cfg:              cfg,
		creds:            creds,
		sessions:         sessions,
		ipCheck:          ipCheck,
		tokens:           tokens,
		loginTmpl:        tmpl,
		rateLimiter:      auth.NewRateLimiter(cfg.RateLimitRequests, window),
		loginRateLimiter: auth.NewRateLimiter(cfg.RateLimitLoginRequests, window),
		rlAllowlist:      rlAllowlist,
		trustedProxies:   trustedProxies,
		customTmpl:       customTmpl,
	}, nil
}

// clientIP resolves the client address for allowlisting and rate limiting.
func (h *Handlers) clientIP(r *http.Request) net.IP {
	return auth.ClientIP(r, h.cfg.TrustForwardedFor, h.trustedProxies)
}

// ForwardAuth is the Traefik forwardAuth endpoint.
// Returns 200 when the request is authenticated, 302 to /login otherwise.
func (h *Handlers) ForwardAuth(w http.ResponseWriter, r *http.Request) {
	clientIP := h.clientIP(r)

	// 1. Check IP allowlist — trusted IPs bypass auth and rate limiting.
	if !h.ipCheck.IsEmpty() {
		if clientIP != nil && h.ipCheck.Allow(clientIP) {
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// 2. Apply rate limiting (skip for IPs in the rate-limit allowlist).
	rateLimitApplies := clientIP != nil && !h.rlAllowlist.Allow(clientIP)
	if rateLimitApplies {
		if !h.rateLimiter.AllowIP(clientIP) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
	}

	// 3. Check Bearer token in Authorization header.
	if !h.tokens.IsEmpty() {
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if h.tokens.Allow(token) {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
	}

	// 4. Check HTTP Basic auth credentials. Never return 401 — if credentials
	// are absent or invalid, fall through to the session/login flow.
	//
	// Failed attempts are charged to the login rate limiter, not the (much
	// larger) general one: otherwise Basic auth would be a password-guessing
	// channel exempt from the login limit. The budget is checked before the
	// password is verified so that a flood cannot force unbounded bcrypt work.
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Basic ") {
		if rateLimitApplies && !h.loginRateLimiter.PeekIP(clientIP) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		username, password, ok := r.BasicAuth()
		switch {
		case ok && h.creds.Verify(username, password):
			if !h.isUserAllowed(username, r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.Header().Set("X-Auth-User", username)
			w.WriteHeader(http.StatusOK)
			return
		case rateLimitApplies:
			h.loginRateLimiter.RecordIP(clientIP)
		}
	}

	// 5. Check session cookie.
	cookie, err := r.Cookie(h.cfg.CookieName)
	if err == nil && cookie.Value != "" {
		sess := h.sessions.Get(cookie.Value)
		// A session outlives its user unless the account is re-checked here:
		// removing someone from the credentials file (and reloading) would
		// otherwise leave them logged in until the session expired, and refreshes
		// keep pushing that expiry back.
		if sess != nil && !h.creds.Exists(sess.Username) {
			h.sessions.Delete(cookie.Value)
			sess = nil
		}
		if sess != nil {
			if !h.isUserAllowed(sess.Username, r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			h.sessions.Refresh(cookie.Value)
			w.Header().Set("X-Auth-User", sess.Username)
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// Not authenticated — redirect to login, encoding the original URI.
	originalURI := r.Header.Get("X-Forwarded-Uri")
	if !isSafePath(originalURI) {
		originalURI = "/"
	}

	proto := forwardedProto(r)
	host := h.forwardedHost(r)

	var loginURL string
	if base := normalizeBaseDomain(h.cfg.BaseDomain); base != "" {
		rd := originalURI
		if host != "" {
			rd = proto + "://" + host + originalURI
		}
		loginURL = proto + "://" + base + "/login?rd=" + url.QueryEscape(rd)
	} else if host != "" {
		// Use the forwarded host/proto for the redirect when available.
		loginURL = proto + "://" + host + "/login?rd=" + url.QueryEscape(originalURI)
	} else {
		// Fall back to a relative redirect when no forwarded host is available.
		loginURL = "/login?rd=" + url.QueryEscape(originalURI)
	}

	http.Redirect(w, r, loginURL, http.StatusFound)
}

// forwardedProto returns the scheme to build redirects with. Only http and
// https are accepted from the header; anything else is ignored so that the
// Location we emit cannot be given an arbitrary scheme.
func forwardedProto(r *http.Request) string {
	switch proto := r.Header.Get("X-Forwarded-Proto"); proto {
	case "http", "https":
		return proto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// forwardedHost returns the X-Forwarded-Host value to build redirects with, or
// "" if it is unusable. The header is client-influenced, so it is only accepted
// when it is a well-formed host and — when a base domain is configured — when it
// belongs to that domain. Without this check, a spoofed X-Forwarded-Host would
// place an attacker's host in the login redirect and in the post-login rd.
func (h *Handlers) forwardedHost(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		return ""
	}
	// Traefik may forward a comma-separated list; the first entry is the host
	// the client asked for.
	if i := strings.IndexByte(host, ','); i >= 0 {
		host = strings.TrimSpace(host[:i])
	}
	if !isValidHost(host) {
		return ""
	}
	if !h.hostAllowed(host) {
		return ""
	}
	return host
}

type loginData struct {
	Error       string
	RedirectURL string
}

// LoginPage renders the login form.
func (h *Handlers) LoginPage(w http.ResponseWriter, r *http.Request) {
	rd := h.sanitizeRedirect(r.URL.Query().Get("rd"), r)
	h.setLoginHeaders(w)
	if err := h.loginTmpl.Execute(w, loginData{RedirectURL: rd}); err != nil {
		log.Printf("template error: %v", err)
	}
}

// setLoginHeaders writes the response headers common to every rendering of the
// login page: never cache a page tied to a session, never leak the rd target
// through Referer, and refuse to be framed so the form cannot be overlaid by a
// third-party site.
func (h *Handlers) setLoginHeaders(w http.ResponseWriter) {
	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Referrer-Policy", "no-referrer")
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("X-Content-Type-Options", "nosniff")

	formAction := h.formAction()

	// The built-in page needs nothing but its own inline stylesheet, so it gets a
	// deny-by-default policy. A custom template may legitimately load its own
	// assets, so only the framing and form-target restrictions are imposed there.
	if h.customTmpl {
		hdr.Set("Content-Security-Policy", "form-action "+formAction+"; frame-ancestors 'none'")
		return
	}
	hdr.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'")
}

// formAction returns the CSP form-action source list for the login page.
//
// The <form> always posts back to its own origin, but a successful login
// redirects to rd, which sanitizeRedirect allows to be any host under
// base_domain — not necessarily the host that served the login page. Chrome
// enforces form-action against the final destination of the navigation a form
// submission produces, including server-side redirects that follow it, so
// 'self' alone makes Chrome silently block the post-login redirect whenever
// it crosses to a sibling subdomain, stranding the user on the login page.
// Firefox does not apply form-action to redirects at all, which is why this
// only shows up in Chrome. Listing the base domain and its subdomains here
// permits exactly the hosts sanitizeRedirect already allows rd to target — it
// does not widen what a login can redirect to.
func (h *Handlers) formAction() string {
	base := normalizeBaseDomain(h.cfg.BaseDomain)
	if base == "" {
		return "'self'"
	}
	return "'self' " + base + " *." + base
}

// LoginSubmit handles credential submission.
func (h *Handlers) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	// Reject cross-site form posts: without this, a third-party page can submit
	// this form on a visitor's behalf (login CSRF), fixing the visitor's session
	// to an account the attacker controls.
	if !h.isSameSiteRequest(r) {
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
		return
	}

	// Apply login rate limiting. Skip for IPs in the auth allowlist or
	// rate-limit allowlist.
	clientIP := h.clientIP(r)
	if clientIP != nil && !h.ipCheck.Allow(clientIP) && !h.rlAllowlist.Allow(clientIP) {
		if !h.loginRateLimiter.AllowIP(clientIP) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	rd := h.sanitizeRedirect(r.FormValue("rd"), r)

	if !h.creds.Verify(username, password) {
		h.setLoginHeaders(w)
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
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/login", http.StatusFound)
}

// isUserAllowed reports whether username is permitted to access the service
// indicated by the current request. It first checks for a service-specific
// user list carried in the configured header (set by a Traefik headers
// middleware and forwarded via authRequestHeaders). If that header is absent,
// it falls back to cfg.DefaultUsers. An empty DefaultUsers list means all
// authenticated users are allowed. The special value "*" in the header means
// all users are allowed regardless of DefaultUsers.
func (h *Handlers) isUserAllowed(username string, r *http.Request) bool {
	headerName := h.cfg.UsersHeader
	if headerName == "" {
		headerName = "X-Lilath-Users"
	}

	if headerVal, ok := h.serviceUsers(r, headerName); ok {
		if headerVal == "*" {
			return true
		}
		for _, u := range splitUsers(headerVal) {
			if u == username {
				return true
			}
		}
		return false
	}

	// No service-specific header — apply the default user list.
	if len(h.cfg.DefaultUsers) == 0 {
		return true
	}
	for _, u := range h.cfg.DefaultUsers {
		if u == username {
			return true
		}
	}
	return false
}

// serviceUsers returns the per-service user list carried in headerName, and
// whether one was present.
//
// The header is meant to be injected by a proxy middleware, but lilath receives
// it as an ordinary request header and cannot tell that apart from a value the
// client sent itself. A client-supplied header can therefore widen its own
// access past default_users — including to "*" — unless the operator either
// strips the header at the proxy edge or sets users_header_secret. When a secret
// is configured the value must be "<secret> <users>"; anything else is treated
// as absent, which falls back to default_users.
func (h *Handlers) serviceUsers(r *http.Request, headerName string) (string, bool) {
	headerVal := strings.TrimSpace(r.Header.Get(headerName))
	if headerVal == "" {
		return "", false
	}

	secret := h.cfg.UsersHeaderSecret
	if secret == "" {
		return headerVal, true
	}

	got, users, found := strings.Cut(headerVal, " ")
	if !found {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
		return "", false
	}
	users = strings.TrimSpace(users)
	if users == "" {
		return "", false
	}
	return users, true
}

// splitUsers splits a comma-separated list of usernames, trimming whitespace.
func splitUsers(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if u := strings.TrimSpace(p); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// sanitizeRedirect returns a safe post-login destination derived from rd.
//
// rd arrives from a query parameter or a form field, i.e. entirely from the
// client, and is handed straight to http.Redirect. Unvalidated, that is an open
// redirect: a link to /login?rd=https://evil.example lands the victim on the
// attacker's site immediately after a real login, which is exactly the shape a
// credential-phishing chain needs. Only same-site destinations are allowed;
// anything else degrades to "/".
func (h *Handlers) sanitizeRedirect(rd string, r *http.Request) string {
	if rd == "" {
		return "/"
	}
	if isSafePath(rd) {
		return rd
	}

	u, err := url.Parse(rd)
	if err != nil || u.Host == "" {
		return "/"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "/"
	}
	if !isValidHost(u.Host) {
		return "/"
	}
	if base := normalizeBaseDomain(h.cfg.BaseDomain); base != "" {
		if !h.hostAllowed(u.Host) {
			return "/"
		}
	} else if !sameHost(u.Host, h.requestHost(r)) {
		// With no base domain configured there is no family of hosts to allow,
		// so only the host lilath was reached on is acceptable.
		return "/"
	}
	return u.String()
}

// isSafePath reports whether s is a root-relative path safe to use as a
// redirect target. It must begin with a single "/" — "//host" and "/\host" are
// both read as protocol-relative URLs by browsers and would leave the site — and
// must not contain control characters, which could split the Location header.
func isSafePath(s string) bool {
	if s == "" || s[0] != '/' {
		return false
	}
	if len(s) > 1 && (s[1] == '/' || s[1] == '\\') {
		return false
	}
	if strings.ContainsAny(s, "\\") {
		return false
	}
	for _, c := range []byte(s) {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// isValidHost reports whether host is a syntactically plausible host or
// host:port, with no characters that could alter the meaning of a URL or split
// a response header.
func isValidHost(host string) bool {
	if host == "" || len(host) > 253+6 {
		return false
	}
	h := hostname(host)
	if h == "" {
		return false
	}
	for _, c := range []byte(host) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == ':' || c == '[' || c == ']' || c == '_':
		default:
			return false
		}
	}
	return true
}

// hostname strips any port and brackets from a host value and lowercases it.
func hostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	// A trailing dot is a valid but distinct spelling of the same name.
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// sameHost reports whether two host values name the same host, ignoring port.
func sameHost(a, b string) bool {
	ha, hb := hostname(a), hostname(b)
	return ha != "" && ha == hb
}

// hostAllowed reports whether host belongs to the configured base domain. It
// returns true when no base domain is configured, because in that deployment
// every protected service has its own host and lilath has nothing to compare
// against.
func (h *Handlers) hostAllowed(host string) bool {
	base := strings.ToLower(normalizeBaseDomain(h.cfg.BaseDomain))
	if base == "" {
		return true
	}
	hn := hostname(host)
	return hn == base || strings.HasSuffix(hn, "."+base)
}

// requestHost returns the host lilath was reached on for this request.
func (h *Handlers) requestHost(r *http.Request) string {
	if host := h.forwardedHost(r); host != "" {
		return host
	}
	return r.Host
}

// isSameSiteRequest reports whether a state-changing request originates from
// this site. It relies on Sec-Fetch-Site where the browser provides it and on
// Origin otherwise; requests carrying neither (curl, scripted clients, very old
// browsers) are allowed through, since there is no cross-site risk without a
// browser to carry ambient credentials.
func (h *Handlers) isSameSiteRequest(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "cross-site":
		return false
	case "same-origin", "same-site", "none":
		return true
	}

	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if sameHost(u.Host, h.requestHost(r)) {
		return true
	}
	// Accept sibling hosts under a configured base domain: a custom login page
	// may legitimately live on another subdomain.
	return normalizeBaseDomain(h.cfg.BaseDomain) != "" && h.hostAllowed(u.Host)
}

func normalizeBaseDomain(base string) string {
	return strings.TrimPrefix(strings.TrimSpace(base), ".")
}

func cookieDomain(base string) string {
	return normalizeBaseDomain(base)
}
