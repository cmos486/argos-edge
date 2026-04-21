# Environment variables

Everything argos reads from the process environment. Values not in
this list are NOT consumed by argos — runtime settings live in the
`settings` table and edit through the panel.

The source of truth is `backend/internal/config/config.go`. This
page mirrors it at the commit that shipped each release; if you
suspect drift, check the code.

## Mandatory secrets

Argos refuses to boot without these.

### `ARGOS_SESSION_SECRET`

- **Type**: string, 32+ bytes recommended.
- **Purpose**: seed for session tokens.
- **How to generate**: `openssl rand -hex 32`.
- **Rotation**: changing it invalidates every existing session on
  the next restart. All users have to re-log-in.

### `ARGOS_MASTER_KEY`

- **Type**: exactly 32 bytes, hex-encoded (64 hex chars).
- **Purpose**: AES-GCM key for at-rest encryption of OIDC
  client_secret, SMTP password, Telegram bot token, VAPID
  private key, TOTP secrets, recovery codes.
- **How to generate**: `openssl rand -hex 32`.
- **Rotation**: non-trivial. Changing the key makes every
  encrypted secret unrecoverable. Keep it safe in a password
  manager and back it up alongside the panel backups (in a
  separate vault so a single leak does not lose both).

## Initial admin bootstrap

Runs exactly once on first boot; subsequent starts are no-ops.

### `ARGOS_INITIAL_ADMIN_USER`

- **Type**: string.
- **Default**: `admin`.
- **Behaviour**: if the user does not exist, create it. If it
  exists, skip. Idempotent.

### `ARGOS_INITIAL_ADMIN_PASSWORD`

- **Type**: string, 8+ chars (bcrypt minimum).
- **Required** if `ARGOS_INITIAL_ADMIN_USER` does not already
  exist — otherwise the boot fails with a clear error.
- **Not required** after first boot. Argos does NOT rotate an
  existing admin's password when this var changes on restart
  (pinned by `TestBootstrap` in the test suite).

## Panel mode

### `ARGOS_PANEL_MODE`

- **Type**: `lan` or `behind_caddy`.
- **Default**: `lan`.
- **Effect**: see [Installation](../getting-started/installation.md#panel-access-modes)
  for the full matrix. Short version:
    - `lan`: port 8080 published, cookies not `Secure`, HSTS not
      sent, `middleware.RealIP` NOT installed (X-Real-IP ignored
      to prevent spoof).
    - `behind_caddy`: port 8080 internal only, cookies `Secure`,
      HSTS + CSP sent, X-Real-IP trusted from Caddy.

### `ARGOS_PANEL_DOMAIN`

- **Type**: string (DNS name).
- **Required** when `ARGOS_PANEL_MODE=behind_caddy`.
- **Used for**: bootstrap host row on first boot (so Caddy starts
  serving the panel immediately), ForwardAuth redirect target.

## Listen + paths

### `ARGOS_LISTEN`

- **Type**: host:port.
- **Default**: `:8080`.
- **Change** only when running argos outside Docker Compose.

### `ARGOS_DB_PATH`

- **Type**: filesystem path.
- **Default**: `./argos.db` (inside the container, mapped to
  `/data/argos.db` via the `argos_data` volume).

### `ARGOS_CADDY_ADMIN`

- **Type**: URL.
- **Default**: `http://localhost:2019` (inside the container; the
  compose file sets it to `http://caddy:2019`).
- **Purpose**: Caddy admin API endpoint for config pushes.

### `ARGOS_CADDY_TLS_DIAL`

- **Type**: host:port.
- **Default**: `caddy:443`.
- **Purpose**: address argos uses when probing Caddy for cert
  state.

### `ARGOS_CADDY_ACCESS_LOG`

- **Type**: filesystem path.
- **Default**: `/var/log/caddy/access.log`.
- **Purpose**: file the log ingestor tails for `caddy_access`
  source rows.

### `ARGOS_CADDY_ERRORS_LOG`

- **Type**: path.
- **Default**: `/var/log/caddy/errors.log`.
- **Purpose**: `caddy_error` source rows.

### `ARGOS_CADDY_WAF_AUDIT_LOG`

- **Type**: path.
- **Default**: `/var/log/caddy/waf-audit.log`.
- **Purpose**: `waf_audit` source rows.

### `ARGOS_CRS_RULES_DIR`

- **Type**: directory path.
- **Default**: `/etc/coraza/crs/rules`.
- **Purpose**: where argos reads the CRS rule list for the panel's
  rule browser + exclusions UI.

## ACME

### `ARGOS_ACME_CA_URL`

- **Type**: URL (https) or empty.
- **Default**: empty (falls back to the `acme.ca_url` setting, which
  itself defaults to Caddy's built-in Let's Encrypt production).
- **Purpose**: hard override of the ACME directory every
  `tls_mode=auto` host asks Caddy to issue against. Survives DB
  restores and Caddy restarts — set it when you need a guaranteed
  CA regardless of what the panel or a backup says.
- **Precedence**: `ARGOS_ACME_CA_URL > host.tls_acme_ca_url > acme.ca_url setting > ""`.
- **Common values**:
    - production: `https://acme-v02.api.letsencrypt.org/directory`
    - staging: `https://acme-staging-v02.api.letsencrypt.org/directory`

When set, it is emitted into the generated Caddy config as the
`ca` field of every ACME issuer on the next reconcile. Unset it
(delete the line + `docker compose up -d`) to return to the
DB-driven setting.

See [Reverse proxy → ACME CA options](../features/reverse-proxy.md#acme-ca-options)
and [Tuning → ACME CA for development](../operations/tuning.md#acme-ca-for-development).

## Logging

### `ARGOS_LOG_LEVEL`

- **Type**: `debug` / `info` / `warn` / `error`.
- **Default**: `info`.
- **Use**: set to `debug` temporarily when diagnosing an issue.
  Chatty; don't leave it on.

## CrowdSec bouncer (read by Caddy, NOT by argos)

These live in `.env` because `docker-compose.yml` forwards them to
the `caddy` container, not to argos. They are listed here for
completeness.

### `CROWDSEC_BOUNCER_API_KEY`

- Paste the key `cscli bouncers add caddy-edge` prints.
- Caddy's bouncer plugin reads this at startup. Changing requires
  a Caddy restart (`docker compose restart caddy`).

### `CLOUDFLARE_API_TOKEN`

- **Required when any host uses `tls_challenge=dns`** (the default).
  Optional otherwise: hosts on `tls_challenge=http` / `tls-alpn`
  never call Cloudflare, and `tls_mode=none` hosts skip ACME
  entirely.
- Scope the token at Cloudflare to `Zone:DNS:Edit` on the zone you
  are managing. Do NOT reuse a Zone:DNS:Write or global API key.
- Caddy's `cloudflare-dns` module reads it at ACME-challenge time;
  argos itself does not call Cloudflare.
- The panel validates at host-create time: saving a host with
  `tls_challenge=dns` while the token is empty returns a clear
  4xx so the misconfiguration surfaces before issuance loops.
- Empty / unset is fine — `docker compose up` no longer hard-fails
  on a missing value (fixed in the 1.0.0 post-release cycle).

## What is NOT in env

Runtime knobs live in the `settings` table and are editable from
the panel UI:

- `logs.retention_days`, `logs.max_entries`
- `session.absolute_timeout_hours`, `session.idle_timeout_hours`
- `backup.schedule`, `backup.retention_days`, `backup.enabled`
- `acme.ca_url` (see [ARGOS_ACME_CA_URL](#argos_acme_ca_url) for
  the env-level override)
- `oidc.*` (issuer, client_id, client_secret_encrypted,
  scopes, cookie_parent_domain, auto_provision, allowed_emails,
  allowed_domains, require_email_verified)
- `crowdsec.*` (enabled, lapi_url, poll_interval_seconds,
  bouncer_api_key, machine_user, machine_password)
- `appsec.mode`
- `notifications.vapid_*`

Full catalog: [Database schema](database-schema.md).

## Suggested `.env` template

```bash
# Mandatory
ARGOS_SESSION_SECRET=<openssl rand -hex 32>
ARGOS_MASTER_KEY=<openssl rand -hex 32>
ARGOS_INITIAL_ADMIN_PASSWORD=<strong password>

# Panel mode
ARGOS_PANEL_MODE=lan
# ARGOS_PANEL_MODE=behind_caddy
# ARGOS_PANEL_DOMAIN=panel.example.com

# Optional but common
ARGOS_INITIAL_ADMIN_USER=admin
ARGOS_LOG_LEVEL=info

# If using CrowdSec:
# CROWDSEC_BOUNCER_API_KEY=<from cscli bouncers add>

# If using DNS-01 ACME with Cloudflare (wildcard certs, typically):
# CLOUDFLARE_API_TOKEN=<Zone:DNS:Edit scoped>
```

## Related

- [Installation](../getting-started/installation.md) — first-run.
- [Upgrading](../operations/upgrading.md) — changes + env.
