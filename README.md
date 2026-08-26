# lilath

A lil' Go web app that acts as a [Traefik `forwardAuth`][fwd] middleware,
providing four layers of access control:

1. **IP allowlist** — requests from listed IPs (or CIDR ranges) are allowed
   immediately, no login required.
2. **Bearer token auth** — requests with a valid `Authorization: Bearer <token>`
   header are authenticated without requiring a login page. Tokens are stored in
   a plain text file, one per line.
3. **HTTP Basic auth** — requests with a valid `Authorization: Basic <credentials>`
   header are authenticated against the credentials file. lilath never returns
   HTTP 401; invalid or missing Basic credentials fall through to the login page.
4. **Credential auth** — everyone else is redirected to a login page.
   Credentials are stored as bcrypt hashes in a plain text file.

[fwd]: https://doc.traefik.io/traefik/middlewares/http/forwardauth/

---

## Quick start

### 1. Build

```bash
go build -o lilath .
go build -o lilath-adduser ./cmd/adduser
```

### 2. Add users

```bash
./lilath-adduser alice        # prompts for password, writes to users.txt
./lilath-adduser -list        # show all usernames
./lilath-adduser -delete bob  # remove a user
./lilath-adduser -f /etc/lilath/users.txt alice   # custom file path
```

---

## Docker

### Build the image

```bash
docker build -t lilath .
```

### Run

```bash
docker run -d \
  --name lilath \
  -p 8080:8080 \
  -v $(pwd)/data:/data \
  lilath
```

Place your `config.yaml` and `users.txt` inside the mounted `/data` directory.
The container runs as a non-root user (`uid 1000`).

### Configure

Configuration can be provided via a YAML file, environment variables, or a
combination of both. Environment variables always take precedence over the
config file.

#### Config file

```bash
cp config.example.yaml config.yaml
$EDITOR config.yaml
```

#### Environment variables

Every config option has a corresponding `LILATH_*` environment variable:

| Environment variable        | Default           | Description                           |
| --------------------------- | ----------------- | ------------------------------------- |
| `LILATH_LISTEN_ADDR`        | `:8080`           | Address/port to bind                  |
| `LILATH_CREDENTIALS_FILE`   | `users.txt`       | Path to credentials file              |
| `LILATH_IP_ALLOWLIST`       | _(empty)_         | Comma-separated IPs/CIDRs that skip auth |
| `LILATH_TRUSTED_PROXIES`    | _(empty)_         | Comma-separated IPs/CIDRs of the proxies in front of lilath |
| `LILATH_SESSION_TTL_MINUTES`| `60`              | Session lifetime in minutes           |
| `LILATH_COOKIE_NAME`        | `lilath_session`  | Session cookie name                   |
| `LILATH_BASE_DOMAIN`        | _(empty)_         | Optional base domain for login/cookie sharing across subdomains |
| `LILATH_COOKIE_SECURE`      | `true`            | Set to `false` for plain HTTP testing |
| `LILATH_TRUST_FORWARDED_FOR`| `true`            | Read client IP from `X-Forwarded-For` |
| `LILATH_LOGIN_TEMPLATE`     | _(empty)_         | Path to a custom HTML login template  |
| `LILATH_TOKENS_FILE`        | _(empty)_         | Path to a Bearer tokens file (one token per line) |
| `LILATH_DEFAULT_USERS`      | _(empty)_         | Comma-separated usernames allowed by default; empty allows all |
| `LILATH_USERS_HEADER`       | `X-Lilath-Users`  | Header carrying per-service allowed usernames |
| `LILATH_USERS_HEADER_SECRET`| _(empty)_         | Shared secret required to prefix the users header value |
| `LILATH_RATE_LIMIT_REQUESTS`| `300`             | Max `GET /auth` requests per IP per window (`0` disables) |
| `LILATH_RATE_LIMIT_LOGIN`   | `10`              | Max `POST /login` attempts per IP per window (`0` disables) |
| `LILATH_RATE_LIMIT_WINDOW`  | `60`              | Rate-limit window size in seconds |
| `LILATH_RATE_LIMIT_ALLOWLIST`| _(empty)_        | Comma-separated IPs/CIDRs exempt from rate limiting |

Boolean variables accept `true`/`1`/`yes`/`on` and `false`/`0`/`no`/`off`.
`LILATH_IP_ALLOWLIST` accepts a comma-separated list (e.g. `127.0.0.1,10.0.0.0/8`).
`LILATH_RATE_LIMIT_ALLOWLIST` also accepts a comma-separated list.
`LILATH_DEFAULT_USERS` accepts a comma-separated list of usernames (e.g. `alice,bob`).
When `LILATH_BASE_DOMAIN` is set (for example `example.com`), unauthenticated
requests are redirected to that domain's `/login` endpoint and session cookies
are written with domain `.example.com` so they are sent to subdomains.

### Run

```bash
./lilath -config config.yaml
```

Reload credentials without restarting:

```bash
kill -HUP <pid>
```

---

## Traefik integration

### Middleware definition

```yaml
# traefik dynamic config
http:
  middlewares:
    lilath-auth:
      forwardAuth:
        address: "http://lilath:8080/auth"
        trustForwardHeader: true
        authRequestHeaders:
          - "Authorization"
          - "X-Lilath-Users"
        authResponseHeaders:
          - "X-Auth-User"
```

### Apply to a router

```yaml
http:
  routers:
    my-app:
      rule: "Host(`app.example.com`)"
      middlewares:
        - lilath-auth
      service: my-app-service
```

### Docker Compose example

The example below uses environment variables so no config file mount is needed.
The only required volume is the credentials file.

```yaml
services:
  traefik:
    image: traefik:v3
    command:
      - --providers.docker=true
      - --entrypoints.web.address=:80
    ports:
      - "80:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  lilath:
    image: lilath   # build your own
    environment:
      LILATH_CREDENTIALS_FILE: /data/users.txt
      LILATH_COOKIE_SECURE: "true"
      LILATH_TRUST_FORWARDED_FOR: "true"
      LILATH_SESSION_TTL_MINUTES: "60"
      # LILATH_IP_ALLOWLIST: "10.0.0.0/8,192.168.0.0/16"
      # LILATH_TRUSTED_PROXIES: "172.16.0.0/12"
    volumes:
      - ./users.txt:/data/users.txt
    healthcheck:
      test: ["CMD-SHELL", "wget -q --spider http://127.0.0.1:8080/healthz || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 10s
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.lilath-login.rule=PathPrefix(`/login`) || PathPrefix(`/logout`)"
      - "traefik.http.routers.lilath-login.entrypoints=web"

  my-app:
    image: my-app
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.my-app.rule=Host(`app.example.com`)"
      - "traefik.http.routers.my-app.middlewares=lilath-auth@docker"
      - "traefik.http.middlewares.lilath-auth.forwardauth.address=http://lilath:8080/auth"
      - "traefik.http.middlewares.lilath-auth.forwardauth.trustForwardHeader=true"
      - "traefik.http.middlewares.lilath-auth.forwardauth.authRequestHeaders=Authorization,X-Lilath-Users"
```

---

## Endpoints

| Method     | Path       | Description                                   |
| ---------- | ---------- | --------------------------------------------- |
| `GET`      | `/healthz` | Healthcheck endpoint — returns 200 when alive |
| _(any)_    | `/auth`    | forwardAuth endpoint — returns 200 or 302     |
| `GET`      | `/login`   | Login page                                    |
| `POST`     | `/login`   | Submit credentials                            |
| `GET/POST` | `/logout`  | Invalidate session                            |

---

## Rate limiting

lilath applies per-IP fixed-window rate limiting by default:

- `GET /auth`: `300` requests per `60` seconds per IP
- `POST /login`: `10` attempts per `60` seconds per IP

When a limit is exceeded, lilath responds with `429 Too Many Requests`.

### Configuration keys (YAML)

Set these keys in `config.yaml`:

```yaml
rate_limit_requests: 300
rate_limit_login_requests: 10
rate_limit_window_seconds: 60
rate_limit_allowlist:
  - "10.0.0.0/8"
  - "192.168.0.0/16"
```

- `rate_limit_requests`: max `GET /auth` requests per IP per window (`0` disables)
- `rate_limit_login_requests`: max `POST /login` attempts per IP per window (`0` disables)
- `rate_limit_window_seconds`: window size in seconds
- `rate_limit_allowlist`: IPs/CIDRs exempt from all rate limiting

Notes:

- IPs already listed in `ip_allowlist` bypass auth and rate limiting.
- `rate_limit_allowlist` is useful for internal monitors, health checks, or trusted networks.

Rate limiting can also be configured with environment variables:

```bash
LILATH_RATE_LIMIT_REQUESTS=300
LILATH_RATE_LIMIT_LOGIN=10
LILATH_RATE_LIMIT_WINDOW=60
LILATH_RATE_LIMIT_ALLOWLIST=10.0.0.0/8,192.168.0.0/16
```

Environment variables override values from `config.yaml`.

---

## Bearer token authentication

As an alternative to the web login page, lilath can authenticate requests that
carry an `Authorization: Bearer <token>` header. This is useful for API clients,
CI pipelines, or other automated tools that cannot interact with a login form.

### Tokens file format

Create a plain text file with one token per line. Lines beginning with `#` and
blank lines are ignored.

```
# tokens.txt — one Bearer token per line
ci-pipeline-token-abc123
monitoring-token-xyz789
```

Point lilath at the file via the `tokens_file` config key or the
`LILATH_TOKENS_FILE` environment variable:

```yaml
tokens_file: "/data/tokens.txt"
```

Tokens are reloaded on `SIGHUP` (same as credentials), so you can add or revoke
tokens without restarting the server:

```bash
kill -HUP <pid>
# or, for Docker:
docker kill --signal=HUP lilath
```

### Using tokens with Traefik

Pass the `Authorization` header through to the forwardAuth endpoint by adding
it to `authRequestHeaders` in your Traefik middleware configuration:

```yaml
http:
  middlewares:
    lilath-auth:
      forwardAuth:
        address: "http://lilath:8080/auth"
        trustForwardHeader: true
        authRequestHeaders:
          - "Authorization"
          - "X-Lilath-Users"
        authResponseHeaders:
          - "X-Auth-User"
```

---

## HTTP Basic authentication

Requests carrying an `Authorization: Basic <credentials>` header are
authenticated directly against the credentials file (the same `username:bcrypt`
file used by the web login page). This is useful for tools and clients that
support HTTP Basic auth natively but cannot interact with a browser-based login
form.

**Important:** lilath never returns HTTP 401. If the Basic credentials are
absent or invalid, the request falls through to the normal session-cookie check
and finally to a redirect to the login page. This avoids triggering unwanted
browser credential dialogs. However, if valid credentials are provided for a
user that is not permitted by the applicable user allowlist (see
[Per-service user restrictions](#per-service-user-restrictions)), lilath
returns HTTP 403 — the same behavior as a session-cookie login for that user.

On success, lilath returns HTTP 200 and sets the `X-Auth-User` response header
to the authenticated username, which Traefik forwards to the upstream service
via `authResponseHeaders`.

No additional configuration is required — Basic auth is enabled automatically
when a credentials file is present.

Because Basic credentials are password guesses, **failed** attempts count against
`rate_limit_login_requests` (the login limiter) rather than the much larger
`rate_limit_requests`. Successful requests are not counted, so a client that
sends Basic credentials on every request is unaffected.

---

## Per-service user restrictions

By default every authenticated user (or token) can reach every service. You
can tighten this so that only specific users are permitted on each service —
without running separate lilath instances.

### How it works

1. Set `default_users` in your config (or `LILATH_DEFAULT_USERS`) to the list
   of usernames that should be allowed on services with no explicit override.
   Leave it empty to allow all authenticated users (the backward-compatible default).
2. Add `X-Lilath-Users` to the `authRequestHeaders` list of the `lilath-auth`
   forwardAuth middleware so Traefik forwards it to lilath.
3. On any service where you want a different set of users, attach a Traefik
   `headers` middleware that sets `X-Lilath-Users` to a comma-separated list of
   allowed usernames. Use `*` to allow every authenticated user on that service.

Token authentication is never restricted by user lists — any valid bearer token
is allowed on every service regardless of `default_users` or `X-Lilath-Users`.

### Example

Suppose `alice` and `bob` are both in `users.txt`. You want:

- **Most services** — only `alice` (via `default_users`)
- **Bob's service** — only `bob`
- **Shared service** — both users

```yaml
# config.yaml
default_users:
  - alice
```

```yaml
# docker-compose.yml (labels on the Traefik / lilath service)
- "traefik.http.middlewares.lilath-auth.forwardauth.address=http://lilath:8080/auth"
- "traefik.http.middlewares.lilath-auth.forwardauth.authRequestHeaders=Authorization,X-Lilath-Users"

# bob-only service: inject X-Lilath-Users=bob before the auth check
- "traefik.http.middlewares.bob-only.headers.customRequestHeaders.X-Lilath-Users=bob"
- "traefik.http.routers.bob-service.middlewares=bob-only,lilath-auth"

# shared service: wildcard overrides default_users, allows everyone
- "traefik.http.middlewares.all-users.headers.customRequestHeaders.X-Lilath-Users=*"
- "traefik.http.routers.shared-service.middlewares=all-users,lilath-auth"

# most services: no extra middleware, default_users applies (alice only)
- "traefik.http.routers.alice-service.middlewares=lilath-auth"
```

> **Middleware order matters.** The `headers` middleware that injects
> `X-Lilath-Users` must appear **before** `lilath-auth` in the middleware
> chain so that Traefik adds the header before forwarding the auth request.

### ⚠️ The users header is only as trustworthy as your proxy config

lilath receives `X-Lilath-Users` as an ordinary request header and **cannot tell
a value injected by your `headers` middleware from one the client sent itself**.
On any router that does *not* attach a `headers` middleware, a client can send
`X-Lilath-Users: *` and escape `default_users` — not past authentication, but
past your per-service segmentation.

Pick one of these if you rely on `default_users`:

**Option A — require a shared secret (recommended).** Set `users_header_secret`
and prefix every header value with it, separated by a space. Values without the
correct secret are ignored, so lilath falls back to `default_users`.

```yaml
# config.yaml
users_header_secret: "a-long-random-string"
```

```yaml
# and in each headers middleware
- "traefik.http.middlewares.bob-only.headers.customRequestHeaders.X-Lilath-Users=a-long-random-string bob"
```

**Option B — strip the header at the edge.** Delete any client-supplied value on
the entrypoint (Traefik removes a header when the custom value is empty), before
per-router middlewares set their own:

```yaml
# traefik static config
entryPoints:
  websecure:
    http:
      middlewares:
        - strip-lilath-users@file

# traefik dynamic config
http:
  middlewares:
    strip-lilath-users:
      headers:
        customRequestHeaders:
          X-Lilath-Users: ""
```

lilath logs a warning at startup when `default_users` is set without
`users_header_secret`.

### `X-Lilath-Users` header values

| Value | Meaning |
|---|---|
| _(absent)_ | Fall back to `default_users`; if that is also empty, allow all |
| `alice,bob` | Only `alice` and `bob` are allowed |
| `*` | All authenticated users are allowed |
| `<secret> alice,bob` | Required form when `users_header_secret` is set; a missing or wrong secret is treated as absent |

### Config reference

```yaml
# Default allowed usernames when no per-service header is present.
# Empty (the default) permits all authenticated users.
default_users:
  - alice

# Header name carrying the per-service user list.
# Defaults to "X-Lilath-Users". Change only if that name conflicts with
# something else in your stack.
# users_header: "X-Lilath-Users"

# Shared secret that must prefix the users header value, separated by a space.
# Without it, a client can send the header itself. Strongly recommended
# whenever default_users is set.
# users_header_secret: "a-long-random-string"
```

---

## Credentials file format

```
# comments are allowed
alice:$2a$10$...bcrypt...
bob:$2a$10$...bcrypt...
```

Use `lilath-adduser` to manage entries safely. You can also generate a hash
manually:

```bash
htpasswd -bnBC 10 "" "mypassword" | tr -d ':\n' | sed 's/$2y/$2a/'
```

---

## Security notes

- Set `cookie_secure: true` (the default) so the session cookie is only sent
  over HTTPS.
- Set `trust_forwarded_for: false` if lilath is exposed directly to untrusted
  networks.
- The session store is in-memory; sessions are lost on restart.

---

## Custom login template

The built-in login page can be replaced with your own HTML template without
recompiling. Set `login_template` in the config file (or the
`LILATH_LOGIN_TEMPLATE` environment variable) to the path of a Go
[`html/template`][html-tmpl] file.

[html-tmpl]: https://pkg.go.dev/html/template

The template receives a single data value with two fields:

| Field          | Type     | Description                                    |
| -------------- | -------- | ---------------------------------------------- |
| `.RedirectURL` | `string` | The URL the user will be sent to after login   |
| `.Error`       | `string` | Non-empty when credentials were rejected       |

Minimal example template:

```html
<!DOCTYPE html>
<html>
<body>
  {{if .Error}}<p style="color:red">{{.Error}}</p>{{end}}
  <form method="POST" action="/login">
    <input type="hidden" name="rd" value="{{.RedirectURL}}">
    <input type="text"     name="username" placeholder="Username" autocomplete="username">
    <input type="password" name="password" placeholder="Password" autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
</body>
</html>
```

### Using a custom template with Docker Compose

Bind-mount your local template file into the container and point
`LILATH_LOGIN_TEMPLATE` at the in-container path:

```yaml
services:
  lilath:
    image: lilath
    environment:
      LILATH_CREDENTIALS_FILE: /data/users.txt
      LILATH_COOKIE_SECURE: "true"
      LILATH_TRUST_FORWARDED_FOR: "true"
      LILATH_LOGIN_TEMPLATE: /data/login.html
    volumes:
      - ./users.txt:/data/users.txt
      - ./login.html:/data/login.html:ro
```

The `:ro` flag makes the bind mount read-only inside the container.
Changes to `login.html` on the host take effect the next time the container
is restarted (the template is read once at startup).

Login responses are sent with `Cache-Control: no-store`, `X-Frame-Options: DENY`
and a `Content-Security-Policy`. The built-in page gets a deny-by-default policy;
a custom template gets only `form-action 'self'; frame-ancestors 'none'`, so it
can load its own assets while still refusing to be framed. When `base_domain`
is set, `form-action` also lists the base domain and its subdomains, since a
successful login can redirect to any host `rd` is allowed to target — without
this, Chrome (unlike Firefox) blocks that redirect because it enforces
`form-action` against the final destination of a form submission, including
any server-side redirect that follows it.

---

## Security notes

lilath is the gate in front of everything behind it, so a few of its defaults
deserve to be understood rather than assumed.

### Client IP determination

The IP allowlist and every rate limiter act on one address per request, and how
that address is chosen matters: getting it wrong means either a bypass of the
allowlist or a bypass of the limits.

With `trust_forwarded_for: true` (the default), lilath reads
`X-Forwarded-For` — but proxies *append* to that header rather than replacing
it, so its leftmost entry is whatever the client sent. lilath therefore walks the
header from the **right**, skipping addresses listed in `trusted_proxies`, and
uses the first address that remains. A client that sends
`X-Forwarded-For: 10.0.0.5` cannot claim to be on your internal network.

Set `trusted_proxies` to the addresses of the proxies in front of lilath:

```yaml
trust_forwarded_for: true
trusted_proxies:
  - "172.16.0.0/12"   # the Docker network Traefik runs on
```

With `trusted_proxies` set, forwarding headers are ignored entirely unless the
connection comes from one of those addresses — so nothing changes even if
lilath's port becomes reachable directly. lilath logs a warning at startup when
`trust_forwarded_for` is enabled and `trusted_proxies` is empty.

If your proxy chain has more than one hop (a CDN in front of Traefik, say), list
every hop; otherwise the address lilath sees is the nearest proxy's, which will
simply fail to match your allowlist rather than allow anything unintended.

### Redirect targets

The `rd` parameter is client-controlled, so lilath only ever redirects to a
root-relative path, to the configured `base_domain` and its subdomains, or to the
host the request arrived on. Anything else falls back to `/`. `X-Forwarded-Host`
is validated the same way before it is used to build a login URL.

### Sessions

Sessions live in memory, are keyed by 256 bits of `crypto/rand`, and are lost on
restart. Every `/auth` hit re-checks that the session's user still exists in the
credentials file, so deleting a user and reloading (`SIGHUP`) ends their session
immediately rather than leaving it valid until it expires.

### Rate limiting and passwords

Failed HTTP Basic credentials on `/auth` are charged to the **login** limiter
(`rate_limit_login_requests`), not the general one, so Basic auth is not a
higher-throughput channel for password guessing. Successful Basic requests are
not charged, so legitimate clients that authenticate on every request keep
working. IPv6 clients are bucketed by `/64` rather than by individual address.

Password verification is bcrypt, which is deliberately slow; unknown usernames
are compared against a dummy hash so response timing does not reveal which
usernames exist.

### What lilath does not do

- It does not terminate TLS. Run it behind a proxy that does, and keep
  `cookie_secure: true` so session cookies are never sent in the clear.
- It does not authenticate the proxy itself. Only your reverse proxy should be
  able to reach lilath's port; do not publish it.
- Bearer tokens are not restricted by `default_users` or the users header. Any
  valid token is accepted for every service.
- The credentials and tokens files are secrets. Mount them read-only where
  possible and keep them out of version control (`.gitignore` covers
  `users.txt` and `config.yaml`).
