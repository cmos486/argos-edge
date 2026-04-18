# syntax=docker/dockerfile:1.7

# ---------- Stage 1: xcaddy build with cloudflare-dns ----------
FROM caddy:2-builder-alpine AS builder

# Only one module for phase 1; Coraza and the CrowdSec bouncer land later.
RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare

# ---------- Stage 2: runtime ----------
FROM caddy:2-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
