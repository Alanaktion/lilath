# lilath

A lil' Go web app that acts as a [Traefik `forwardAuth`][fwd] middleware,
providing three layers of access control:

1. **IP allowlist** — requests from listed IPs (or CIDR ranges) are allowed
   immediately, no login required.
2. **Bearer token auth** — requests with a valid `Authorization: Bearer <token>`
   header are authenticated without requiring a login page. Tokens are stored in
   a plain text file, one per line.
3. **Credential auth** — everyone else is redirected to a login page.
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

### Managing users from outside the container

Because the credentials file is a plain bind-mounted file, you can manage
users **without entering the running container** by spinning up a temporary
container that shares the same volume:

```bash
# Add or update a user (interactive password prompt)
docker run --rm -it \
  --entrypoint lilath-adduser \
  -v $(pwd)/data:/data \
  lilath \
  -f /data/users.txt alice

# List all users
docker run --rm \
  --entrypoint lilath-adduser \
  -v $(pwd)/data:/data \
  lilath \
  -f /data/users.txt -list

# Delete a user
docker run --rm \
  --entrypoint lilath-adduser \
  -v $(pwd)/data:/data \
  lilath \
  -f /data/users.txt -delete alice
```

After writing the file, send `SIGHUP` to the running container so it picks up
the changes without restarting:

```bash
docker kill --signal=HUP lilath
```

If you prefer named Docker volumes instead of bind mounts, use
`--volumes-from` to share the volume with the temporary container:

```bash
docker run --rm -it --volumes-from lilath --entrypoint lilath-adduser lilath -f /data/users.txt alice
docker kill --signal=HUP lilath
```

### 3. Configure

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
| `LILATH_SESSION_SECRET`     | _(empty)_         | Optional session signing secret       |
| `LILATH_SESSION_TTL_MINUTES`| `60`              | Session lifetime in minutes           |
| `LILATH_COOKIE_NAME`        | `lilath_session`  | Session cookie name                   |
| `LILATH_BASE_DOMAIN`        | _(empty)_         | Optional base domain for login/cookie sharing across subdomains |
| `LILATH_COOKIE_SECURE`      | `true`            | Set to `false` for plain HTTP testing |
| `LILATH_TRUST_FORWARDED_FOR`| `true`            | Read client IP from `X-Forwarded-For` |
| `LILATH_LOGIN_TEMPLATE`     | _(empty)_         | Path to a custom HTML login template  |
| `LILATH_TOKENS_FILE`        | _(empty)_         | Path to a Bearer tokens file (one token per line) |
| `LILATH_RATE_LIMIT_REQUESTS`| `300`             | Max `GET /auth` requests per IP per window (`0` disables) |
| `LILATH_RATE_LIMIT_LOGIN`   | `10`              | Max `POST /login` attempts per IP per window (`0` disables) |
| `LILATH_RATE_LIMIT_WINDOW`  | `60`              | Rate-limit window size in seconds |
| `LILATH_RATE_LIMIT_ALLOWLIST`| _(empty)_        | Comma-separated IPs/CIDRs exempt from rate limiting |

Boolean variables accept `true`/`1`/`yes`/`on` and `false`/`0`/`no`/`off`.
`LILATH_IP_ALLOWLIST` accepts a comma-separated list (e.g. `127.0.0.1,10.0.0.0/8`).
`LILATH_RATE_LIMIT_ALLOWLIST` also accepts a comma-separated list.
When `LILATH_BASE_DOMAIN` is set (for example `example.com`), unauthenticated
requests are redirected to that domain's `/login` endpoint and session cookies
are written with domain `.example.com` so they are sent to subdomains.

### 4. Run

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
      # LILATH_SESSION_SECRET: "change-me"
    volumes:
      - ./users.txt:/data/users.txt
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
```

---

## Endpoints

| Method     | Path      | Description                               |
| ---------- | --------- | ----------------------------------------- |
| `GET`      | `/auth`   | forwardAuth endpoint — returns 200 or 302 |
| `GET`      | `/login`  | Login page                                |
| `POST`     | `/login`  | Submit credentials                        |
| `GET/POST` | `/logout` | Invalidate session                        |

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

### Environment variables

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
        authResponseHeaders:
          - "X-Auth-User"
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
