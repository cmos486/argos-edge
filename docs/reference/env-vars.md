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

- **Optional.** Only required when a host uses TLS `mode=dns01` with
  the Cloudflare provider. Typical case: wildcard cert on a
  Cloudflare-managed zone. Every other TLS path (`tls_mode=auto`
  with HTTP-01, `tls_mode=none`) ignores the value.
- Scope the token at Cloudflare to `Zone:DNS:Edit` on the zone you
  are managing. Do NOT reuse a Zone:DNS:Write or global API key.
- Caddy's `cloudflare-dns` module reads it at ACME-challenge time;
  argos itself does not call Cloudflare.
- Empty / unset is fine — `docker compose up` no longer hard-fails
  on a missing value (fixed in the 1.0.0 post-release cycle).

## What is NOT in env

Runtime knobs live in the `settings` table and are editable from
the panel UI:

- `logs.retention_days`, `logs.max_entries`
- `session.absolute_timeout_hours`, `session.idle_timeout_hours`
- `backup.schedule`, `backup.retention_days`, `backup.enabled`
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
