# Copilot Instructions

## Build & Test

```bash
# Build both binaries
go build -o lilath .
go build -o lilath-adduser ./cmd/adduser

# Build all packages (CI check)
go build ./...

# Run all tests
go test ./...

# Run a single test
go test ./internal/auth/ -run TestName
go test ./internal/config/ -run TestName
go test ./internal/server/ -run TestName
```

## Architecture

lilath is a Traefik `forwardAuth` middleware: Traefik forwards every request to `GET /auth`, and lilath returns 200 (allow) or 302 (redirect to `/login`).

There are two binaries:
- **`lilath`** — the main HTTP server (`main.go` → `internal/server`, `internal/auth`, `internal/config`)
- **`lilath-adduser`** — CLI tool to manage the credentials file (`cmd/adduser`)

**Auth flow in `GET /auth`** (in priority order):
1. IP allowlist → allow immediately, skip rate limiting
2. Rate limiter → 429 if exceeded (unless IP is in rate-limit allowlist)
3. Bearer token (`Authorization: Bearer <token>`) → allow if in tokens file
4. Session cookie → allow and refresh if valid
5. Not authenticated → redirect to `/login?rd=<original-uri>`

**Package layout:**
- `internal/config` — YAML config + `LILATH_*` env var overlay (env always wins)
- `internal/auth` — `Credentials`, `SessionStore`, `TokenStore`, `IPChecker`, `RateLimiter`
- `internal/server` — `Handlers` (HTTP handlers) + `Server` (stdlib `http.Server`)

## Key Conventions

**Config:** All options live in `internal/config/config.go`. Every new field needs both a YAML struct tag and a corresponding `LILATH_*` env var in `applyEnv()`.

**Credentials / tokens files:** Plain text, `username:bcrypt_hash` or one-token-per-line. Lines starting with `#` and blank lines are ignored. Both are reloaded live on `SIGHUP` without restarting.

**Thread safety:** All shared state (`Credentials`, `SessionStore`, `TokenStore`, `RateLimiter`) uses `sync.RWMutex` or `sync.Mutex`. New shared types must follow the same pattern.

**Atomic file writes:** `auth.WriteCredentials` writes to a temp file then `os.Rename` — use this pattern for any file write that must not corrupt a partially-written file.

**Session store is in-memory only** — sessions are lost on restart; there is no persistence layer.

**Login template:** The built-in template is embedded via `//go:embed templates` in `internal/server/handlers.go`. Custom templates receive `.RedirectURL` and `.Error` fields.

**`X-Auth-User` header:** Set on the response when a session is valid; Traefik passes it to the upstream service via `authResponseHeaders`.

**Docker image:** Published to `ghcr.io/alanaktion/lilath`, multi-arch (amd64/arm64). Semver tags → versioned releases; `main` → `edge`.
