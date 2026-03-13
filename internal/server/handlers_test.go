package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alanaktion/lilath/internal/auth"
	"github.com/alanaktion/lilath/internal/config"
	"github.com/alanaktion/lilath/internal/server"
)

const (
	testUser     = "testuser"
	testPassword = "testpassword"
	cookieName   = "test_session"
)

// newTestServer returns an httptest.Server for the full handler stack, and a
// credentials store so callers can interact with it directly if needed.
func newTestServer(t *testing.T) (*httptest.Server, *auth.Credentials) {
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

	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
	}

	sessions := auth.NewSessionStore(cfg.SessionTTL)

	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}

	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	srv := server.NewServer(":0", h)

	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	return ts, creds
}

// login performs a POST /login and returns the session cookie, or fails the test.
func login(t *testing.T, ts *httptest.Server) *http.Cookie {
	t.Helper()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	form := url.Values{
		"username": {testUser},
		"password": {testPassword},
		"rd":       {"/"},
	}
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /login: expected %d, got %d", http.StatusFound, resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatal("POST /login: no session cookie in response")
	return nil
}

// noFollowClient returns an *http.Client that does not follow redirects.
func noFollowClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// --------------------------------------------------------------------------
// GET /auth — forward-auth endpoint
// --------------------------------------------------------------------------

func TestForwardAuth_Unauthenticated(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	resp, err := client.Get(ts.URL + "/auth")
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestForwardAuth_UnauthenticatedWithURI(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.Header.Set("X-Forwarded-Uri", "/path?foo=bar&baz=qux")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}

	// The rd parameter must preserve all query params of the original URI.
	loc := resp.Header.Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parsing Location %q: %v", loc, err)
	}
	if got := parsed.Query().Get("rd"); got != "/path?foo=bar&baz=qux" {
		t.Fatalf("rd param: expected %q, got %q", "/path?foo=bar&baz=qux", got)
	}
}

func TestForwardAuth_Authenticated(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	cookie := login(t, ts)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with session: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := resp.Header.Get("X-Auth-User"); got != testUser {
		t.Fatalf("X-Auth-User: expected %q, got %q", testUser, got)
	}
}

func TestForwardAuth_IPAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")
	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
	}

	sessions := auth.NewSessionStore(cfg.SessionTTL)

	// httptest uses 127.0.0.1 as the remote address.
	ipCheck, err := auth.NewIPChecker([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}

	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	srv := server.NewServer(":0", h)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/auth")
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d for allowed IP, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestForwardAuth_WithForwardedHostProto(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")
	req.Header.Set("X-Forwarded-Uri", "/protected")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://example.com/login") {
		t.Fatalf("expected absolute redirect to example.com, got %q", loc)
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parsing Location %q: %v", loc, err)
	}
	if got := parsed.Query().Get("rd"); got != "/protected" {
		t.Fatalf("rd param: expected %q, got %q", "/protected", got)
	}
}

func TestForwardAuth_WithBaseDomain(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "asdf.example.com")
	req.Header.Set("X-Forwarded-Uri", "/protected?x=1")

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
	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
		BaseDomain:        "example.com",
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	rr := httptest.NewRecorder()
	h.ForwardAuth(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://example.com/login") {
		t.Fatalf("expected absolute redirect to base domain, got %q", loc)
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parsing Location %q: %v", loc, err)
	}
	if got := parsed.Query().Get("rd"); got != "https://asdf.example.com/protected?x=1" {
		t.Fatalf("rd param: expected absolute original URL, got %q", got)
	}

}

// --------------------------------------------------------------------------
// Bearer token auth — GET /auth with Authorization: Bearer <token>
// --------------------------------------------------------------------------

// newTestServerWithTokens returns an httptest.Server configured with a
// TokenStore loaded from the given tokens slice.
func newTestServerWithTokens(t *testing.T, tokens []string) *httptest.Server {
	t.Helper()

	dir := t.TempDir()

	usersPath := filepath.Join(dir, "users.txt")
	creds, err := auth.LoadCredentials(usersPath)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	tokensContent := strings.Join(tokens, "\n") + "\n"
	tokensPath := filepath.Join(dir, "tokens.txt")
	if err := os.WriteFile(tokensPath, []byte(tokensContent), 0600); err != nil {
		t.Fatalf("WriteFile tokens: %v", err)
	}
	tokenStore, err := auth.LoadTokens(tokensPath)
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}

	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, tokenStore)
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	srv := server.NewServer(":0", h)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	return ts
}

func TestForwardAuth_BearerToken_ValidToken(t *testing.T) {
	ts := newTestServerWithTokens(t, []string{"my-secret-token"})
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.Header.Set("Authorization", "Bearer my-secret-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with Bearer: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d for valid Bearer token, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestForwardAuth_BearerToken_InvalidToken(t *testing.T) {
	ts := newTestServerWithTokens(t, []string{"my-secret-token"})
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with bad Bearer: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d for invalid Bearer token, got %d", http.StatusFound, resp.StatusCode)
	}
}

func TestForwardAuth_BearerToken_NoTokensConfigured(t *testing.T) {
	// When no tokens are configured, Bearer headers are ignored.
	ts, _ := newTestServer(t)
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with Bearer (no tokens configured): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d when no tokens configured, got %d", http.StatusFound, resp.StatusCode)
	}
}

func TestForwardAuth_BearerToken_EmptyTokenStore(t *testing.T) {
	// A token file containing only comments should behave the same as no file.
	ts := newTestServerWithTokens(t, []string{"# only comments"})
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with Bearer (empty token store): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d for empty token store, got %d", http.StatusFound, resp.StatusCode)
	}
}

// --------------------------------------------------------------------------
// GET /login — login page
// --------------------------------------------------------------------------

func TestLoginPage_GET(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected text/html, got %q", ct)
	}
}

func TestLoginPage_GET_WithRd(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/login?rd=/dashboard")
	if err != nil {
		t.Fatalf("GET /login?rd=: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

// --------------------------------------------------------------------------
// POST /login — credential submission
// --------------------------------------------------------------------------

func TestLoginSubmit_ValidCredentials(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	form := url.Values{
		"username": {testUser},
		"password": {testPassword},
		"rd":       {"/"},
	}
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}

	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie after successful login")
	}
	if sessionCookie.Value == "" {
		t.Fatal("session cookie value should not be empty")
	}
}

func TestLoginSubmit_SetsCookieDomainWithBaseDomain(t *testing.T) {
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

	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
		BaseDomain:        "example.com",
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	form := url.Values{
		"username": {testUser},
		"password": {testPassword},
		"rd":       {"https://asdf.example.com/"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.LoginSubmit(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}

	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie after successful login")
	}
	if sessionCookie.Domain != "example.com" {
		t.Fatalf("cookie domain: expected %q, got %q", "example.com", sessionCookie.Domain)
	}
}

func TestLoginSubmit_InvalidPassword(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	form := url.Values{
		"username": {testUser},
		"password": {"wrongpassword"},
		"rd":       {"/"},
	}
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestLoginSubmit_UnknownUser(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	form := url.Values{
		"username": {"nobody"},
		"password": {testPassword},
		"rd":       {"/"},
	}
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestLoginSubmit_RedirectsToRd(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	form := url.Values{
		"username": {testUser},
		"password": {testPassword},
		"rd":       {"/dashboard"},
	}
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/dashboard" {
		t.Fatalf("expected redirect to /dashboard, got %q", loc)
	}
}

// --------------------------------------------------------------------------
// GET /logout and POST /logout
// --------------------------------------------------------------------------

func TestLogout_GET(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	cookie := login(t, ts)

	// Confirm session is active.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth before logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected authenticated before logout, got %d", resp.StatusCode)
	}

	// Logout.
	logoutReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("GET /logout: %v", err)
	}
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, logoutResp.StatusCode)
	}

	// Session should now be invalid.
	authReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	authReq.AddCookie(cookie)
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("GET /auth after logout: %v", err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("expected unauthenticated after logout, got %d", authResp.StatusCode)
	}
}

func TestLogout_POST(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	cookie := login(t, ts)

	logoutReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("POST /logout: %v", err)
	}
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, logoutResp.StatusCode)
	}

	// Session should now be invalid.
	authReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	authReq.AddCookie(cookie)
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("GET /auth after POST /logout: %v", err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("expected unauthenticated after logout, got %d", authResp.StatusCode)
	}
}

func TestLogout_ClearsCookie(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	cookie := login(t, ts)

	logoutReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/logout", nil)
	logoutReq.AddCookie(cookie)
	resp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("GET /logout: %v", err)
	}
	defer resp.Body.Close()

	// Check that a Set-Cookie header clears the session cookie.
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			if c.MaxAge >= 0 {
				t.Fatalf("expected MaxAge < 0 to clear cookie, got %d", c.MaxAge)
			}
			return
		}
	}
	t.Fatal("expected a Set-Cookie header for the session cookie on logout")
}

func TestLogout_ClearsCookieDomainWithBaseDomain(t *testing.T) {
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

	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
		BaseDomain:        "example.com",
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	sid, err := sessions.Create(testUser)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	rr := httptest.NewRecorder()

	h.Logout(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	var cleared *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			cleared = c
			break
		}
	}
	if cleared == nil {
		t.Fatal("expected a Set-Cookie header for the session cookie on logout")
	}
	if cleared.Domain != "example.com" {
		t.Fatalf("cookie domain: expected %q, got %q", "example.com", cleared.Domain)
	}
}

// --------------------------------------------------------------------------
// Custom login template
// --------------------------------------------------------------------------

func TestLoginPage_CustomTemplate(t *testing.T) {
dir := t.TempDir()

// Write a minimal custom template.
tmplPath := filepath.Join(dir, "custom-login.html")
if err := os.WriteFile(tmplPath, []byte(`<!DOCTYPE html><html><body id="custom">{{.RedirectURL}}</body></html>`), 0600); err != nil {
t.Fatalf("WriteFile: %v", err)
}

path := filepath.Join(dir, "users.txt")
creds, err := auth.LoadCredentials(path)
if err != nil {
t.Fatalf("LoadCredentials: %v", err)
}

cfg := &config.Config{
CookieName:    cookieName,
CookieSecure:  false,
SessionTTL:    60,
LoginTemplate: tmplPath,
}
sessions := auth.NewSessionStore(cfg.SessionTTL)
ipCheck, err := auth.NewIPChecker(nil)
if err != nil {
t.Fatalf("NewIPChecker: %v", err)
}
h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
if err != nil {
t.Fatalf("NewHandlers: %v", err)
}

req := httptest.NewRequest(http.MethodGet, "/login?rd=/dashboard", nil)
rr := httptest.NewRecorder()
h.LoginPage(rr, req)
resp := rr.Result()
defer resp.Body.Close()

if resp.StatusCode != http.StatusOK {
t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
}
body, err := io.ReadAll(resp.Body)
if err != nil {
t.Fatalf("ReadAll: %v", err)
}
if !strings.Contains(string(body), `id="custom"`) {
t.Errorf("response body does not contain custom template marker: %s", body)
}
if !strings.Contains(string(body), "/dashboard") {
t.Errorf("response body does not contain redirect URL: %s", body)
}
}

func TestNewHandlers_InvalidCustomTemplate(t *testing.T) {
creds, err := auth.LoadCredentials(filepath.Join(t.TempDir(), "users.txt"))
if err != nil {
t.Fatalf("LoadCredentials: %v", err)
}
cfg := &config.Config{
CookieName:    cookieName,
SessionTTL:    60,
LoginTemplate: "/nonexistent/path/login.html",
}
sessions := auth.NewSessionStore(cfg.SessionTTL)
ipCheck, err := auth.NewIPChecker(nil)
if err != nil {
t.Fatalf("NewIPChecker: %v", err)
}
_, err = server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
if err == nil {
t.Fatal("expected error for nonexistent template path, got nil")
}
}
