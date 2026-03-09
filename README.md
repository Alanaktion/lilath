# lilath

A lil' Go web app that acts as a [Traefik `forwardAuth`][fwd] middleware,
providing two layers of access control:

1. **IP allowlist** — requests from listed IPs (or CIDR ranges) are allowed
   immediately, no login required.
2. **Credential auth** — everyone else is redirected to a login page.
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
| `LILATH_COOKIE_SECURE`      | `true`            | Set to `false` for plain HTTP testing |
| `LILATH_TRUST_FORWARDED_FOR`| `true`            | Read client IP from `X-Forwarded-For` |

Boolean variables accept `true`/`1`/`yes`/`on` and `false`/`0`/`no`/`off`.
`LILATH_IP_ALLOWLIST` accepts a comma-separated list (e.g. `127.0.0.1,10.0.0.0/8`).

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
