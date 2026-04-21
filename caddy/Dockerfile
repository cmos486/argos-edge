# syntax=docker/dockerfile:1.7
#
# Custom Caddy build. Pinned versions (verified at each release tag):
#   - coraza-caddy/v2           v2.5.0    (phase 4)
#   - caddy-ratelimit           v0.1.0    (phase 4)
#   - coreruleset               v4.25.0   (phase 4 LTS; CVE-2026-33691 fix)
#   - caddy-dns/cloudflare      latest    (phase 1 + v1.3 panel-managed creds)
#   - caddy-dns/route53         latest    (v1.3.0-alpha: first non-Cloudflare
#                                          native DNS-01 provider; panel
#                                          streams AWS creds inline via
#                                          /load rather than env vars.)
#   - caddy-crowdsec-bouncer    v0.12.1   (phase 7; requires Caddy >=2.7.3)
#   - caddy-crowdsec-bouncer/appsec  v0.12.1  (AppSec WAF inline: explicit
#      --with so the http.handlers.appsec handler is fully linked rather
#      than relying on a transitive import that omits the api-key code.)
#
# Caddy base image is pinned to 2.11.x so a new minor upstream does not
# silently change module ABI under our feet on CI rebuilds. Bump when
# adding a provider that bumps its required Caddy version; no automatic
# major-version chases.

# ---------- Stage 1: xcaddy build ----------
FROM caddy:2.11-builder-alpine AS builder

RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/caddy-dns/route53 \
    --with github.com/corazawaf/coraza-caddy/v2@v2.5.0 \
    --with github.com/mholt/caddy-ratelimit@v0.1.0 \
    --with github.com/hslatman/caddy-crowdsec-bouncer@v0.12.1 \
    --with github.com/hslatman/caddy-crowdsec-bouncer/http@v0.12.1 \
    --with github.com/hslatman/caddy-crowdsec-bouncer/appsec@v0.12.1

# ---------- Stage 2: fetch CRS + stage config ----------
FROM alpine:3.20 AS rules
ARG CRS_VERSION=v4.25.0
RUN apk add --no-cache curl tar
RUN mkdir -p /etc/coraza/crs \
    && curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" \
       -o /tmp/crs.tar.gz \
    && tar -xzf /tmp/crs.tar.gz -C /tmp \
    && mv /tmp/coreruleset-*/rules /etc/coraza/crs/rules \
    && mv /tmp/coreruleset-*/crs-setup.conf.example /etc/coraza/crs-setup.conf \
    && rm -rf /tmp/crs.tar.gz /tmp/coreruleset-*

# Minimal Coraza base config the panel's generated directives @include at
# the top of every per-host WAF config. Audit log is written as one JSON
# record per transaction so the argos ingestor can tail it.
RUN mkdir -p /etc/coraza && cat > /etc/coraza/coraza.conf <<'EOF'
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecResponseBodyLimit 524288
SecResponseBodyLimitAction ProcessPartial
SecPcreMatchLimit 500
SecPcreMatchLimitRecursion 500
SecAuditEngine RelevantOnly
SecAuditLog /var/log/caddy/waf-audit.log
SecAuditLogFormat JSON
SecAuditLogParts ABIJDEFHKZ
SecAuditLogType Serial
SecArgumentSeparator &
SecCookieFormat 0
SecTmpDir /tmp
SecDataDir /tmp
EOF

# ---------- Stage 3: runtime ----------
FROM caddy:2.11-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY --from=rules /etc/coraza /etc/coraza
