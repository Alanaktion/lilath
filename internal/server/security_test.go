package server_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alanaktion/lilath/internal/auth"
	"github.com/alanaktion/lilath/internal/config"
	"github.com/alanaktion/lilath/internal/server"
)

// testEnv bundles the pieces of a handler stack a test may need to manipulate.
type testEnv struct {
	handlers  *server.Handlers
	sessions  *auth.SessionStore
	creds     *auth.Credentials
	credsPath string
}

// newHandlers builds a Handlers with testUser in the credentials file, applying
// cfg as-is apart from the fields every test needs.
func newHandlers(t *testing.T, cfg *config.Config) *testEnv {
	t.Helper()

	path := filepath.Join(t.TempDir(), "users.txt")
	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{testUser: hash}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}
	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	if cfg.CookieName == "" {
		cfg.CookieName = cookieName
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 60
	}

	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker(cfg.IPAllowlist)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	return &testEnv{handlers: h, sessions: sessions, creds: creds, credsPath: path}
}

// postLogin submits the login form directly to the handler and returns the
// response. Extra headers can be supplied to simulate browser fetch metadata.
func postLogin(t *testing.T, h *server.Handlers, rd string, headers map[string]string) *http.Response {
	t.Helper()

	form := url.Values{
		"username": {testUser},
		"password": {testPassword},
		"rd":       {rd},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "auth.example.com"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.LoginSubmit(rr, req)
	return rr.Result()
}

// --------------------------------------------------------------------------
// Open redirect
// --------------------------------------------------------------------------

// TestLoginSubmit_RejectsOffsiteRedirect covers the open redirect: rd is fully
// client-controlled, so a valid login must never bounce the browser to a host
// outside the deployment.
func TestLoginSubmit_RejectsOffsiteRedirect(t *testing.T) {
	hostile := []string{
		"https://evil.example/",
		"http://evil.example/path",
		"//evil.example/",
		"/\\evil.example",
		"\\\\evil.example",
		"https://auth.example.com.evil.example/",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"/path\r\nX-Injected: 1",
	}

	for _, rd := range hostile {
		t.Run(rd, func(t *testing.T) {
			env := newHandlers(t, &config.Config{BaseDomain: "example.com"})
			resp := postLogin(t, env.handlers, rd, nil)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusFound {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
			}
			if loc := resp.Header.Get("Location"); loc != "/" {
				t.Errorf("Location = %q, want %q — rd %q was not neutralized", loc, "/", rd)
			}
		})
	}
}

func TestLoginSubmit_AllowsSafeRedirects(t *testing.T) {
	tests := []struct {
		name       string
		baseDomain string
		rd         string
		want       string
	}{
		{name: "relative path", rd: "/dashboard", want: "/dashboard"},
		{name: "relative path with query", rd: "/a?b=c&d=e", want: "/a?b=c&d=e"},
		{name: "base domain itself", baseDomain: "example.com", rd: "https://example.com/x", want: "https://example.com/x"},
		{name: "subdomain of base", baseDomain: "example.com", rd: "https://app.example.com/x", want: "https://app.example.com/x"},
		{name: "own host without base domain", rd: "https://auth.example.com/x", want: "https://auth.example.com/x"},
		{name: "other host without base domain", rd: "https://other.example.com/x", want: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newHandlers(t, &config.Config{BaseDomain: tt.baseDomain})
			resp := postLogin(t, env.handlers, tt.rd, nil)
			defer resp.Body.Close()

			if loc := resp.Header.Get("Location"); loc != tt.want {
				t.Errorf("Location = %q, want %q", loc, tt.want)
			}
		})
	}
}

func TestLoginPage_NeutralizesRedirectInForm(t *testing.T) {
	env := newHandlers(t, &config.Config{BaseDomain: "example.com"})

	req := httptest.NewRequest(http.MethodGet, "/login?rd=https://evil.example/", nil)
	rr := httptest.NewRecorder()
	env.handlers.LoginPage(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	body := rr.Body.String()
	if strings.Contains(body, "evil.example") {
		t.Errorf("login form carries the hostile rd value:\n%s", body)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want %q", got, "DENY")
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("CSP missing frame-ancestors: %q", resp.Header.Get("Content-Security-Policy"))
	}
}

// TestLoginPage_FormActionAllowsBaseDomainRedirect ensures the login page's
// CSP form-action directive includes the base domain and its subdomains when
// base_domain is configured. Without this, Chrome blocks the post-login
// redirect whenever rd lands on a sibling subdomain, since Chrome (unlike
// Firefox) enforces form-action against the final destination of a form
// submission's redirect chain, not just the immediate POST target.
func TestLoginPage_FormActionAllowsBaseDomainRedirect(t *testing.T) {
	env := newHandlers(t, &config.Config{BaseDomain: "example.com"})

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	env.handlers.LoginPage(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"'self'", "example.com", "*.example.com"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP form-action missing %q: %q", want, csp)
		}
	}
}

// TestLoginPage_FormActionSelfOnlyWithoutBaseDomain ensures no base domain is
// configured leaves form-action at a plain 'self', since every redirect target
// is then necessarily same-host.
func TestLoginPage_FormActionSelfOnlyWithoutBaseDomain(t *testing.T) {
	env := newHandlers(t, &config.Config{})

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	env.handlers.LoginPage(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self';") {
		t.Errorf("CSP form-action = %q, want plain 'self'", csp)
	}
}

// --------------------------------------------------------------------------
// Forwarded host / proto handling
// --------------------------------------------------------------------------

// TestForwardAuth_RejectsSpoofedForwardedHost ensures a forged X-Forwarded-Host
// cannot steer the login redirect (or the rd embedded in it) to another site.
func TestForwardAuth_RejectsSpoofedForwardedHost(t *testing.T) {
	env := newHandlers(t, &config.Config{BaseDomain: "example.com"})

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-Uri", "/protected")
	rr := httptest.NewRecorder()
	env.handlers.ForwardAuth(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://example.com/login") {
		t.Fatalf("Location = %q, want a redirect to the base domain", loc)
	}
	if strings.Contains(loc, "evil.example") {
		t.Errorf("Location carries the spoofed host: %q", loc)
	}
}

func TestForwardAuth_RejectsHostileForwardedProtoAndURI(t *testing.T) {
	env := newHandlers(t, &config.Config{})

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Forwarded-Proto", "javascript")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Uri", "//evil.example/")
	rr := httptest.NewRecorder()
	env.handlers.ForwardAuth(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http://app.example.com/login") {
		t.Fatalf("Location = %q, want the scheme to fall back to http", loc)
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parsing %q: %v", loc, err)
	}
	if rd := parsed.Query().Get("rd"); rd != "/" {
		t.Errorf("rd = %q, want %q — a protocol-relative URI was accepted", rd, "/")
	}
}

// --------------------------------------------------------------------------
// Login CSRF
// --------------------------------------------------------------------------

func TestLoginSubmit_RejectsCrossSitePost(t *testing.T) {
	env := newHandlers(t, &config.Config{})

	resp := postLogin(t, env.handlers, "/", map[string]string{"Sec-Fetch-Site": "cross-site"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d for a cross-site login post", resp.StatusCode, http.StatusForbidden)
	}
	if len(resp.Cookies()) != 0 {
		t.Error("a cross-site login post must not set a session cookie")
	}
}

func TestLoginSubmit_RejectsForeignOrigin(t *testing.T) {
	env := newHandlers(t, &config.Config{})

	resp := postLogin(t, env.handlers, "/", map[string]string{"Origin": "https://evil.example"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d for a foreign Origin", resp.StatusCode, http.StatusForbidden)
	}
}

func TestLoginSubmit_AcceptsSameSiteAndScriptedPosts(t *testing.T) {
	tests := []map[string]string{
		nil,
		{"Sec-Fetch-Site": "same-origin"},
		{"Sec-Fetch-Site": "none"},
		{"Origin": "https://auth.example.com"},
	}

	for _, headers := range tests {
		env := newHandlers(t, &config.Config{})
		resp := postLogin(t, env.handlers, "/", headers)
		if resp.StatusCode != http.StatusFound {
			t.Errorf("headers %v: status = %d, want %d", headers, resp.StatusCode, http.StatusFound)
		}
		resp.Body.Close()
	}
}

func TestLoginSubmit_AcceptsOriginOnBaseDomain(t *testing.T) {
	env := newHandlers(t, &config.Config{BaseDomain: "example.com"})

	resp := postLogin(t, env.handlers, "/", map[string]string{"Origin": "https://app.example.com"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d for an Origin under the base domain", resp.StatusCode, http.StatusFound)
	}
}

// --------------------------------------------------------------------------
// Basic auth brute force
// --------------------------------------------------------------------------

// TestForwardAuth_BasicAuthUsesLoginRateLimit covers a bypass of the login
// limiter: password guesses sent as Basic credentials to /auth were only bound
// by the much larger general request limit.
func TestForwardAuth_BasicAuthUsesLoginRateLimit(t *testing.T) {
	env := newHandlers(t, &config.Config{
		RateLimitRequests:      1000,
		RateLimitLoginRequests: 3,
		RateLimitWindowSeconds: 60,
	})

	guess := func() int {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.RemoteAddr = "203.0.113.9:1234"
		req.SetBasicAuth(testUser, "wrong-password")
		rr := httptest.NewRecorder()
		env.handlers.ForwardAuth(rr, req)
		return rr.Code
	}

	for i := 1; i <= 3; i++ {
		if status := guess(); status == http.StatusTooManyRequests {
			t.Fatalf("guess %d: got 429 while still within the login limit", i)
		}
	}
	if status := guess(); status != http.StatusTooManyRequests {
		t.Fatalf("guess 4: status = %d, want %d", status, http.StatusTooManyRequests)
	}
}

// TestForwardAuth_BasicAuthSuccessNotRateLimited confirms valid Basic requests
// keep working: only failures consume the login budget.
func TestForwardAuth_BasicAuthSuccessNotRateLimited(t *testing.T) {
	env := newHandlers(t, &config.Config{
		RateLimitRequests:      1000,
		RateLimitLoginRequests: 3,
		RateLimitWindowSeconds: 60,
	})

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.RemoteAddr = "203.0.113.9:1234"
		req.SetBasicAuth(testUser, testPassword)
		rr := httptest.NewRecorder()
		env.handlers.ForwardAuth(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i, rr.Code, http.StatusOK)
		}
	}
}

// --------------------------------------------------------------------------
// Session revocation
// --------------------------------------------------------------------------

// TestForwardAuth_SessionRevokedWhenUserRemoved covers account revocation:
// deleting a user and reloading must end their session, not leave it valid until
// it expires (which refreshes keep postponing).
func TestForwardAuth_SessionRevokedWhenUserRemoved(t *testing.T) {
	env := newHandlers(t, &config.Config{})

	sid, err := env.sessions.Create(testUser)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	authRequest := func() int {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
		rr := httptest.NewRecorder()
		env.handlers.ForwardAuth(rr, req)
		return rr.Code
	}

	if status := authRequest(); status != http.StatusOK {
		t.Fatalf("status = %d, want %d before removal", status, http.StatusOK)
	}

	// Remove the user from the credentials file and reload, as SIGHUP does.
	if err := auth.WriteCredentials(env.credsPath, map[string]string{}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}
	if err := env.creds.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if status := authRequest(); status == http.StatusOK {
		t.Fatal("session still valid after the user was removed from the credentials file")
	}
}

// --------------------------------------------------------------------------
// Users header spoofing
// --------------------------------------------------------------------------

// TestForwardAuth_UsersHeaderSecret covers privilege escalation through the
// per-service users header: lilath cannot distinguish a header injected by a
// proxy middleware from one sent by the client, so with a secret configured an
// unsigned header must be ignored rather than trusted to widen access.
func TestForwardAuth_UsersHeaderSecret(t *testing.T) {
	tests := []struct {
		name       string
		headerVal  string
		wantStatus int
	}{
		{name: "no header falls back to default_users", headerVal: "", wantStatus: http.StatusForbidden},
		{name: "client-supplied wildcard ignored", headerVal: "*", wantStatus: http.StatusForbidden},
		{name: "client-supplied list ignored", headerVal: testUser, wantStatus: http.StatusForbidden},
		{name: "wrong secret ignored", headerVal: "wrong-secret " + testUser, wantStatus: http.StatusForbidden},
		{name: "correct secret honoured", headerVal: "s3cret " + testUser, wantStatus: http.StatusOK},
		{name: "correct secret with wildcard", headerVal: "s3cret *", wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newHandlers(t, &config.Config{
				DefaultUsers:      []string{"someone-else"},
				UsersHeaderSecret: "s3cret",
			})
			sid, err := env.sessions.Create(testUser)
			if err != nil {
				t.Fatalf("Create session: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/auth", nil)
			req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
			if tt.headerVal != "" {
				req.Header.Set("X-Lilath-Users", tt.headerVal)
			}
			rr := httptest.NewRecorder()
			env.handlers.ForwardAuth(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
		})
	}
}

// --------------------------------------------------------------------------
// IP allowlist spoofing
// --------------------------------------------------------------------------

// TestForwardAuth_SpoofedXFFDoesNotBypassIPAllowlist is the end-to-end form of
// the allowlist bypass: claiming an allowlisted source address in
// X-Forwarded-For must not produce a blanket 200.
func TestForwardAuth_SpoofedXFFDoesNotBypassIPAllowlist(t *testing.T) {
	env := newHandlers(t, &config.Config{
		IPAllowlist:       []string{"10.0.0.0/8"},
		TrustForwardedFor: true,
		TrustedProxies:    []string{"127.0.0.1"},
	})

	// The client sent its own X-Forwarded-For; the proxy appended the real peer.
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "10.0.0.5, 203.0.113.9")
	rr := httptest.NewRecorder()
	env.handlers.ForwardAuth(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatal("spoofed X-Forwarded-For granted the IP allowlist bypass")
	}

	// A request genuinely relayed for an allowlisted client is still allowed.
	req = httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "10.0.0.5")
	rr = httptest.NewRecorder()
	env.handlers.ForwardAuth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d for a genuinely allowlisted client", rr.Code, http.StatusOK)
	}
}

func TestForwardAuth_ForwardedHeadersIgnoredFromUntrustedPeer(t *testing.T) {
	env := newHandlers(t, &config.Config{
		IPAllowlist:       []string{"10.0.0.0/8"},
		TrustForwardedFor: true,
		TrustedProxies:    []string{"192.0.2.1"},
	})

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.RemoteAddr = "203.0.113.9:1234" // not a trusted proxy
	req.Header.Set("X-Forwarded-For", "10.0.0.5")
	rr := httptest.NewRecorder()
	env.handlers.ForwardAuth(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatal("forwarding headers from an untrusted peer granted the allowlist bypass")
	}
}

// --------------------------------------------------------------------------
// Request limits
// --------------------------------------------------------------------------

func TestLoginSubmit_RejectsOversizedBody(t *testing.T) {
	env := newHandlers(t, &config.Config{})

	body := "username=" + strings.Repeat("a", 1<<20) + "&password=x"
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	env.handlers.LoginSubmit(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d for an oversized login body", rr.Code, http.StatusBadRequest)
	}
}

func TestForwardAuth_AllowsNonGETMethods(t *testing.T) {
	env := newHandlers(t, &config.Config{})
	srv := server.NewServer(":0", env.handlers)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	client := noFollowClient()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/auth", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /auth: %v", err)
	}
	defer resp.Body.Close()

	// The auth decision must be made, not refused with 405, in case the proxy is
	// configured to preserve the original request method.
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
}
