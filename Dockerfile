# syntax=docker/dockerfile:1

# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/lilath . && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/lilath-adduser ./cmd/adduser

# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM alpine:3.21

# ca-certificates for any outbound TLS; tzdata for correct log timestamps.
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 lilath

COPY --from=builder /out/lilath        /usr/local/bin/lilath
COPY --from=builder /out/lilath-adduser /usr/local/bin/lilath-adduser

# Config and credentials are expected to be mounted here.
WORKDIR /data
VOLUME ["/data"]

USER lilath
EXPOSE 8080

ENTRYPOINT ["lilath"]
CMD ["-config", "/data/config.yaml"]
