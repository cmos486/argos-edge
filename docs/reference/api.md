# HTTP API

Flat reference of every route the panel exposes. Authoritative
source: `backend/internal/server/server.go` — if drift shows up
between this page and the binary, the code wins.

Response shape for errors is uniformly
`{"error":"<message>"}` with an HTTP status in 4xx/5xx. Success
responses are per-endpoint; listings return `[...]` arrays
(never `null`), single-row GETs return an object.

## Auth posture

Two groups:

- **Public** — no session cookie required. Endpoints used before
  login (password/OIDC/TOTP exchange) plus a few probe endpoints.
- **Authed** — `Authenticate` middleware demands a valid
  `argos_session` cookie.

## Public endpoints

### Health / probes

| Method | Path | Purpose |
|---|---|---|
| GET  | `/healthz` | Liveness. Returns `ok`. Unauthed. |
| GET  | `/api/healthz` | Same, under the API mount. |

### Authentication

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/auth/login` | Username + password. Returns session cookie on success, or `{requires_totp: true, challenge_id}` if TOTP is enabled. |
| POST | `/api/auth/totp/verify` | Exchange challenge_id + 6-digit code for a session cookie. |
| POST | `/api/auth/totp/recovery` | Exchange challenge_id + recovery code for a session cookie. |

### OIDC SSO

| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/auth/oidc/available` | `{enabled: bool}` — used by the Login page to decide whether to render the SSO button. |
| GET  | `/api/auth/oidc/login?rd=<url>` | 302 to the IdP with PKCE + state. |
| GET  | `/api/auth/oidc/callback?code=&state=` | IdP lands the user here; exchanges code, mints session, redirects. |

### ForwardAuth + redirect validator

| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/auth/forward` | ForwardAuth sub-request. Returns 200 + X-Auth-* headers, or 302 to /login. |
| GET  | `/api/auth/safe-redirect?rd=<url>` | `{url: <safe>}` — resolves a post-login return target through the allowlist. |

## Authed endpoints

### Auth lifecycle

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/auth/logout` | Delete session + evict ForwardAuth cache. 204. |
| GET  | `/api/auth/me` | `{username}` for the current session. |

### TOTP management

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/auth/totp/setup` | Generate secret + 10 recovery codes. Returns one-shot payload. |
| POST | `/api/auth/totp/activate` | Confirm enrollment with a fresh code. |
| POST | `/api/auth/totp/disable` | Disable 2FA; requires password + code (or recovery). |
| GET  | `/api/auth/totp/status` | `{enabled, enabled_at, setup_pending, recovery_codes_remaining}`. |
| POST | `/api/auth/totp/recovery/regenerate` | Mint 10 new recovery codes, invalidate the old set. Requires password. |

### OIDC admin plane

| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/auth/oidc/status` | Scrubbed view of the config (no plaintext client_secret). |
| PUT  | `/api/auth/oidc/config` | Update the OIDC settings (issuer/client/scopes/allowlist/auto_provision/require_email_verified/cookie_parent_domain). |
| POST | `/api/auth/oidc/test` | Probe discovery against an issuer URL. Returns advertised endpoints. |

### Hosts

| Method | Path | Purpose |
|---|---|---|
| GET    | `/api/hosts` | List. |
| POST   | `/api/hosts` | Create. |
| GET    | `/api/hosts/{id}` | One. |
| PUT    | `/api/hosts/{id}` | Update (full replace; partial fields take a `*bool` shape). |
| DELETE | `/api/hosts/{id}` | Delete. |
| POST   | `/api/hosts/{id}/toggle` | Toggle the enabled flag. |

The host record carries (most relevant for v1.3.18+):

- `lan_only` (v1.3.18) — when true, Caddy gates the host with a
  remote_ip matcher that returns 403 to public IPs.
- `true_detect_mode` (v1.3.19, activated v1.3.29) — when true,
  the panel writes a profiles.yaml entry that suppresses LAPI
  decision creation for AppSec alerts whose target_fqdn matches
  this host. Useful for hosts whose legitimate traffic triggers
  AppSec false positives (socket.io polling, monitoring tools).
  See [Per-host true_detect_mode](../features/crowdsec.md) and
  the v1.3.29 release notes for the profiles.yaml splice
  protocol.
- `tls_acme_ca_url` (v1.3.7) — per-host override of the global
  ACME CA URL.
- `tls_challenge` (v1.3.7) — `dns` / `http` / `tls-alpn`.
- `tls_dns_provider` (v1.3+) — names the dns_providers row this
  host pulls credentials from when `tls_challenge='dns'`.

### Rules (per-host)

| Method | Path | Purpose |
|---|---|---|
| GET    | `/api/hosts/{host_id}/rules` | List. |
| POST   | `/api/hosts/{host_id}/rules` | Create. |
| POST   | `/api/hosts/{host_id}/rules/reorder` | Reorder by priority (atomic). |
| GET    | `/api/hosts/{host_id}/rules/{rule_id}` | One. |
| PUT    | `/api/hosts/{host_id}/rules/{rule_id}` | Update. |
| DELETE | `/api/hosts/{host_id}/rules/{rule_id}` | Delete. |
| POST   | `/api/hosts/{host_id}/rules/{rule_id}/toggle` | Toggle enabled. |

### Host security (WAF + rate limit)

| Method | Path | Purpose |
|---|---|---|
| GET    | `/api/hosts/{host_id}/security` | Full security row. |
| PUT    | `/api/hosts/{host_id}/security` | Update WAF mode/paranoia + rate limit fields. |
| POST   | `/api/hosts/{host_id}/security/exclusions` | Create exclusion. |
| PUT    | `/api/hosts/{host_id}/security/exclusions/{id}` | Update. |
| DELETE | `/api/hosts/{host_id}/security/exclusions/{id}` | Delete. |
| POST   | `/api/hosts/{host_id}/security/exclusions/{id}/toggle` | Toggle. |
| POST   | `/api/hosts/{host_id}/security/custom-rules` | Create SecRule. |
| PUT    | `/api/hosts/{host_id}/security/custom-rules/{id}` | Update. |
| DELETE | `/api/hosts/{host_id}/security/custom-rules/{id}` | Delete. |
| POST   | `/api/hosts/{host_id}/security/custom-rules/{id}/toggle` | Toggle. |

### Per-host security overview (v1.3.20)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/security/overview` | Aggregate: WAF enabled count per mode, rate-limit enabled count, ForwardAuth enabled count, cert expiry stats. |

For the broader `/api/security/*` namespace (decisions,
whitelist, scenarios management, drift detection, country bans),
see the [Security tabs](#security-tabs-crowdsec-surface-v1324)
section below.

### Target groups + targets

| Method | Path | Purpose |
|---|---|---|
| GET    | `/api/target-groups` | List. |
| POST   | `/api/target-groups` | Create. |
| GET    | `/api/target-groups/{id}` | Detail + targets. |
| PUT    | `/api/target-groups/{id}` | Update. |
| DELETE | `/api/target-groups/{id}` | Delete (400 if in use). |
| POST   | `/api/target-groups/{id}/targets` | Add target. |
| PUT    | `/api/target-groups/{id}/targets/{target_id}` | Update target. |
| DELETE | `/api/target-groups/{id}/targets/{target_id}` | Delete target. |
| POST   | `/api/target-groups/{id}/targets/{target_id}/toggle` | Toggle. |

### Certs

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/certs` | Caddy-issued cert state mirror, enriched with status / days_left / last_event / next_renewal_estimate / challenge. |
| POST | `/api/certs/{host_id}/renew` | Ask Caddy to re-check this cert; actual renewal only fires inside the ~30-day window. Returns 202. |

### Manual certs (v1.1)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/manual-certs` | List all operator-uploaded certs (metadata only; never the key). |
| GET | `/api/manual-certs/{host_id}` | One cert's metadata. 404 when the host has no manual cert. |
| POST | `/api/manual-certs/{host_id}` | Multipart upload: `cert_pem`, `key_pem`, optional `chain_pem`. Validates + encrypts the key + writes files to the shared volume + flips the host to `tls_mode=manual`. |
| DELETE | `/api/manual-certs/{host_id}?revert=auto\|none` | Remove the cert + files, revert the host's TLS mode (default `auto`). |
| GET | `/api/manual-certs/{host_id}/download` | Stream cert + chain PEM for inspection (key is never served). |

See [Manual certificates](../features/manual-certs.md) for validation semantics and the
`manual_cert_expiring_soon` notification event.

### Logs

Full surface under `/api/logs/...` — list, stream (SSE tail),
stats, timeseries, single row. Wired via
`h.RouteLogsMux(r)`; the exact shape is in
`internal/api/logs.go`.

### Settings

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/settings?prefix=<p>` | List with optional prefix filter. |
| PUT | `/api/settings/{key}` | Update one setting. |

### Notifications

| Method | Path | Purpose |
|---|---|---|
| GET    | `/api/notifications/event-types` | Catalog for the UI picker. |
| GET    | `/api/notifications/channels` | List. |
| POST   | `/api/notifications/channels` | Create. |
| GET    | `/api/notifications/channels/{id}` | One. |
| PUT    | `/api/notifications/channels/{id}` | Update. |
| DELETE | `/api/notifications/channels/{id}` | Delete (also drops the rate-limit bucket). |
| POST   | `/api/notifications/channels/{id}/toggle` | Toggle enabled. |
| POST   | `/api/notifications/channels/{id}/test` | Send a test event. |
| GET    | `/api/notifications/rules` | List. |
| POST   | `/api/notifications/rules` | Create. |
| GET    | `/api/notifications/rules/{id}` | One. |
| PUT    | `/api/notifications/rules/{id}` | Update. |
| DELETE | `/api/notifications/rules/{id}` | Delete. |
| POST   | `/api/notifications/rules/{id}/toggle` | Toggle enabled. |
| GET    | `/api/notifications/deliveries` | Delivery history. |
| GET    | `/api/notifications/deliveries/{id}` | One delivery detail. |
| POST   | `/api/notifications/deliveries/{id}/retry` | Retry a delivery through the worker. |
| GET    | `/api/notifications/recent-alerts` | Recent high-severity rows for the UI banner. |

### Web Push

| Method | Path | Purpose |
|---|---|---|
| GET    | `/api/push/vapid-public-key` | VAPID public key for the service worker. |
| POST   | `/api/push/subscribe` | Create subscription for the current user. |
| DELETE | `/api/push/subscribe` | Remove current user's subscription. |
| GET    | `/api/push/subscriptions` | List across all users. |

### Backups

| Method | Path | Purpose |
|---|---|---|
| GET    | `/api/backups` | List. |
| POST   | `/api/backups` | Create manual backup. |
| GET    | `/api/backups/{id}` | Metadata. |
| DELETE | `/api/backups/{id}` | Delete row + file on disk. |
| GET    | `/api/backups/{id}/download` | Download the tar.gz. |
| POST   | `/api/backups/{id}/restore` | Schedule in-place restore (requires container restart). |
| POST   | `/api/backups/upload-and-restore` | Upload an archive not on the panel + schedule restore. |

### Config import/export

| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/config/export.yaml` | Export panel config as YAML. |
| POST | `/api/config/import/validate` | Validate a YAML import before applying. |
| POST | `/api/config/import/apply` | Apply a validated import. |

### Dashboard

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/dashboard/overview` | Header cards (hosts, backends, certs, alerts). |
| GET | `/api/dashboard/traffic` | Traffic chart data. |
| GET | `/api/dashboard/security` | Attack signal aggregates + map + top IPs. |
| GET | `/api/dashboard/health` | Health card data. |

### System

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/system/health` | Rich struct: memory, goroutines, DB pool, worker queue, scheduler, panel mode, uptime. |

### Security tabs (CrowdSec surface; v1.3.24+)

The legacy `/api/threats/*` paths were retired in v1.3.24 in
favour of one consolidated `/api/security/*` namespace that maps
1:1 to the panel's `/security` tab strip.

#### Banned IPs / Whitelist / Activity / status

| Method | Path | Purpose |
|---|---|---|
| GET    | `/api/security/decisions?q=&scope=&origin=&limit=&offset=` | Active decisions list. Filters: substring `q` (matches value or scenario), `scope` (`Ip`/`Range`/`Country`/`AS`), `origin` (e.g. `cscli`, `argos-country-BR`, `CAPI`). Cached for 15s. |
| DELETE | `/api/security/decisions/{id}` | Unban a single decision. Idempotent (404 from LAPI = already gone, returns success). |
| POST   | `/api/security/decisions/unban-ip` | Body: `{ip: "..."}`. Removes every active decision for that IP. |
| GET    | `/api/security/whitelist` | List manual whitelist entries. Returns `{entries: [...]}`. |
| POST   | `/api/security/whitelist` | Body: `{scope: "ip"\|"range", value, reason}`. Persists + writes the `argos-whitelist-entries.txt` sentinel. |
| DELETE | `/api/security/whitelist/{id}` | Remove a row + rewrite the sentinel. |
| GET    | `/api/security/audit-log?limit=&offset=` | Activity tab feed (panel + WAF + bouncer events from `log_entries`). |
| GET    | `/api/security/dashboard-stats` | Aggregated counters for the Banned IPs tab header. |
| GET    | `/api/security/check-self` | SelfBlockBanner v2 data: panel's session IPs + public IP, cross-referenced against active bans. |
| GET    | `/api/security/public-ip-self` | Cached panel public IP (refreshed hourly via ipify). |
| GET    | `/api/security/overview` | Per-host security posture aggregates. |
| GET    | `/api/crs/rules` | Browse the CRS rule list for the WAF exclusions UI. |

#### Scenarios management (v1.3.25)

| Method | Path | Purpose |
|---|---|---|
| GET    | `/api/security/scenarios` | List installed scenarios. Returns `{scenarios: [{short_name, source, canonical_name, path, disabled, description?}], is_available, mount_path, disabled_count, last_modified_at?}`. The `description` field (v1.3.30) carries the hub-catalogue summary for the tooltip; empty when the slimmed `argos-scenarios-index.json` hasn't been emitted yet. |
| PATCH  | `/api/security/scenarios/{name}` | Body: `{disabled: bool}`. Toggles the operator-disabled set. The `name` segment is URL-encoded (`crowdsecurity%2FCVE-2017-9841`); chi v5 captures the encoded form, the handler `url.PathUnescape`s before persisting. Writes `argos-disabled-scenarios.txt` sentinel. |

#### AppSec tuning (v1.3.25)

| Method | Path | Purpose |
|---|---|---|
| GET    | `/api/security/appsec-tuning` | Current thresholds: `{inbound_threshold, outbound_threshold, last_modified_at?}`. |
| PATCH  | `/api/security/appsec-tuning` | Partial update; either or both of `inbound_threshold` / `outbound_threshold` (range 1..100). Writes `argos-appsec-tuning.txt` sentinel. |

#### Drift detection (v1.3.27)

| Method | Path | Purpose |
|---|---|---|
| GET    | `/api/security/drift` | Combined snapshot from the 60s reconciler tick. Response: `{scenarios: {drift_detected, expected_disabled, actually_enabled, last_check_at}, appsec_tuning: {drift_detected, expected_inbound, actual_inbound, expected_outbound, actual_outbound, last_check_at}, last_check_at}`. |

The mark-applied endpoints (`/api/security/scenarios/mark-applied`,
`/api/security/appsec-tuning/mark-applied`) shipped in v1.3.25
were retired in v1.3.27 along with the operator-trust model.

#### Country bans (v1.3.21+ + v1.3.31 async + v1.3.33 reconciler)

| Method | Path | Purpose |
|---|---|---|
| POST   | `/api/security/countries/{cc}/expand` | **v1.3.31 path-based shape.** Body: `{duration: "168h", reason?: ""}`. Returns 202 + the new job row (state=pending). Worker goroutine drives the LAPI POST chunk-by-chunk; poll `/api/security/jobs/{id}` for progress. |
| GET    | `/api/security/countries` | List active expansions. Each row carries the v1.3.33 `state` field (`active` \| `drifted`). |
| DELETE | `/api/security/countries/{cc}` | Synchronous revoke: `DELETE /v1/decisions?origins=argos-country-XX` to LAPI + `DELETE FROM country_ban_expansions` panel-side. |

The pre-v1.3.31 body-based `POST /api/security/countries/expand`
endpoint is removed.

#### Job polling (v1.3.31)

| Method | Path | Purpose |
|---|---|---|
| GET    | `/api/security/jobs/{id}` | One job row. 404 when missing. |
| GET    | `/api/security/jobs?country=XX&limit=N` | List recent jobs. Empty `country` returns cross-country recent. `limit` defaults 20, max 200. |

The `/api/security/jobs` path is intentionally top-level under
`/security/` (not nested under `/countries`) to leave room for
future job types (audit retention sweeps, scenario re-installs,
etc.) without further URL churn.

### GeoIP

| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/geoip/lookup?ip=<ip>` | Country + ASN for one IP. |
| GET  | `/api/geoip/status` | DB versions, last refresh, attribution. |
| POST | `/api/geoip/refresh` | Kick a manual mmdb download. |

### AppSec (WAF runtime)

| Method | Path | Purpose |
|---|---|---|
| GET   | `/api/appsec/status` | Mode + last-change metadata + collections count. |
| GET   | `/api/appsec/metrics` | Rolling aggregates over a window (1h/6h/12h/24h). |
| PATCH | `/api/appsec/mode` | Change runtime mode (detect/block/disabled). Reconciler re-pushes Caddy config. |

### Caddy

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/caddy/status` | Health of the Caddy admin API from argos' perspective. |

## SPA fallback

Anything not matching `/healthz` or `/api/*` falls through to the
embedded SPA's `index.html` so client-side routing works.

## Content types

- Requests: `application/json` for mutations. `multipart/form-data`
  for backup uploads.
- Responses: `application/json; charset=utf-8` uniformly. SSE
  streams (log tail) serve `text/event-stream`.

## Related

- [Env vars](env-vars.md) — bootstrap config.
- [CLI](cli.md) — subcommands that bypass the API (break-glass).
- [Request flow](../architecture/request-flow.md) — how these
  handlers chain with Caddy.
