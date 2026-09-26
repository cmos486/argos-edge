# Storage

One SQLite file. WAL mode with `NORMAL` synchronous, foreign keys
on, 5-second busy timeout. Two handles on the file since v1.3.41.0:
the writer (`db.Open`, `SetMaxOpenConns(1)`, so writes always go
through the same connection and contention stays bounded) and a
read-only pool (`db.OpenReadOnly`, `mode=ro`, `query_only`, two
connections) that GET handlers and the read side of the background
components use. The table of what reads where is in
[Read pool](#read-pool-v13410).

## Why SQLite

Argos is single-writer by design: one panel instance, one Go
process, one admin. SQLite is the right fit:

- Zero-config. No Postgres container, no tuning pool, no network
  DB.
- Atomic backups via `VACUUM INTO`.
- WAL gives concurrent readers (log browser + dashboard polling
  the DB while the worker writes) without the writer blocking.
  Until v1.3.40.4 argos did not use that: every read went through
  the one writer connection, so a purge batch or a checkpoint fsync
  queued every request behind it (v1.3.40.1 incident, v1.3.40
  planning doc section 4). The read pool of v1.3.41.0 is what makes
  this bullet true.
- Fits in a container with nothing alongside.

The trade-off is HA: a single file means no leader election and
no primary failover. For a homelab that is fine. For HA, this
project is the wrong pick.

## WAL + pragmas

From `internal/db/db.go`:

```go
dsn := fmt.Sprintf("file:%s?%s", path, url.Values{
    "_pragma": []string{
        "journal_mode(WAL)",
        "foreign_keys(1)",
        "busy_timeout(5000)",
        "synchronous(NORMAL)",
    },
}.Encode())
d.SetMaxOpenConns(1)
```

- `WAL` gives concurrent readers + single writer without the
  reader-blocking checkpoint of rollback journal mode.
- `synchronous=NORMAL` is the usual WAL companion: commits fsync
  the WAL but not the main DB file on every commit, at the cost
  of up to one commit of replay work after an OS crash. Durable
  for commit fsync events; acceptable for a homelab.
- `busy_timeout=5000` buys the pool 5 s of wait room on any lock
  contention.
- `SetMaxOpenConns(1)` flattens concurrent writes through a single
  connection; prevents `SQLITE_BUSY` even when background
  goroutines write during heavy request traffic. Reads no longer
  share it (below).

## Read pool (v1.3.41.0)

`db.OpenReadOnly` opens the same file with `mode=ro` and
`PRAGMA query_only`, `busy_timeout(5000)`, two connections
(`db.ReadPoolSize`): one for the request that is running, one for the
next, so a long GET (CSV export) does not queue every other GET. A
write through it fails at the SQLite level. Each statement is its own
WAL snapshot: a GET sees every commit that finished before it started
(a host created by POST is in the next GET, a logout answers 401 at
once); nothing is cached across statements. Both handles are opened
after `backup.ApplyPending` replaces the file on boot, so a restore
(flag written by `POST /api/backups/{id}/restore` or `argos restore`,
applied on the next start) is seen by both; the running process never
swaps the file under an open handle.

`ARGOS_READ_POOL=0` (kill-switch, `.env` + `make deploy-prod`) skips
the second handle and every reader below falls back to the writer,
which is the v1.3.40.4 behaviour.

Where each read goes. "Pool" means the handler or method uses
`h.reader()` / the component's `ReadDB`; "writer" means `h.DB`.

| Handler or component | Reads from | Why |
|---|---|---|
| Every GET handler in `internal/api` (hosts, rules, target groups, certs, manual certs, DNS providers, logs list/detail/stats/timeseries/stream/export/pipeline, settings list, security overview / whitelist / audit log / dashboard stats / scenarios / tuning / drift / check-self, threats, AppSec status and metrics, TOTP status, OIDC available/status/login, safe-redirect, config export) | pool | Pure reads; nothing in the request writes before them |
| `Authenticate` middleware: `session.Lookup`, cookie parent domain setting | pool | Runs on every authenticated request; on the writer it waited for each purge batch and each checkpoint fsync (the stall the pool exists for) |
| `Authenticate` middleware: `session.Touch` | writer | An UPDATE of `last_seen_at` at most once per 5 min per session |
| Shared read helpers also used by mutating handlers (`requireHost`, `loadOIDCConfigOrError`, `safeReturnTo`, `scenariosReader`, `resolveHostDomains`) | pool | Existence and config reads before a write; a stale answer produces the same 404 / 409 the write itself would |
| Dashboard cache loaders (`dashboard.Queries`, `securityLoader`, `certProbes`) | pool | They run in the cache goroutine every 24 s; the 24 h traffic query held the writer about 0.8 s on prod |
| `notifications.NotifRepo` List / Get / Stats / RecentAlerts / push-sub lists / `ActiveRulesFor` | pool | Reads; the worker's `InsertDelivery` / `UpdateDelivery` and the channel/rule writes stay on the writer |
| `backup.Manager.List` / `Get` | pool | Reads of the `backups` table; `Create`, `Delete` and the reconcile stay on the writer |
| `country.Expander.List`, `country.JobRunner.Get` / `ListByCountry` | pool | Reads; expansion, revoke and job state changes stay on the writer |
| `appsec.StatusReader`, `hardening.TimeoutCache` | pool (constructed with the read handle) | They only read settings and mounted files |
| `OIDCCallback` | writer | Upserts the user and creates the session, then answers from those rows in the same request |
| `ForwardAuth` | writer | Public route outside the middleware; does its own `session.Touch` |
| `Login`, `Logout`, TOTP flows, `RegenerateCrowdSecCredentials` | writer | Write, then read back their own write (session, recovery codes, credentials) |
| Every POST / PUT / PATCH / DELETE handler | writer | Mutations; their pre-write reads go through the shared helpers above |
| `publicip.Detector` (`Status`, `Get`) | writer | The refresh persists through the same handle; one cached read per request path, not worth a second handle |
| `SystemHealth` `h.DB.Stats()` | writer | It reports the writer pool's connection stats |
| Ingestor batches, retention purge, reconcilers, drift detector, notification worker and crons, backup scheduler, login rate limiter | writer | Background writers; unchanged |

## Schema ownership

Every schema change lives under `backend/migrations/` as a
numbered pair of `.up.sql` + `.down.sql` files. A few bigger
migrations ship as Go hooks (`.go` files registered in
`migrations.go`) when the logic cannot be expressed in SQL alone.

The runner in `internal/db/migrate.go`:

- Creates `schema_migrations(version, applied_at)` if missing.
- Applies any `.up.sql` not in the applied set, in lexical order
  of the version prefix.
- Each migration runs in its own transaction; partial failure
  rolls back cleanly.
- Idempotent — running `Migrate()` twice is a no-op the second
  time.
- Go hooks override the matching SQL file when both exist
  (migration 005 is the only active example).

Full runner invariants + squash policy live in
`backend/migrations/README.md`. The short answer: 19 migrations
today, no squash planned before the count exceeds 40 or a major
version break happens.

## Table catalog

Rough ownership map, grouped by concern. Field lists are the
operator-visible columns, not the full schema. See
[reference/database-schema.md](../reference/database-schema.md)
for the per-column detail.

### Identity + auth

- **`users`** — id, username, password_hash (nullable for
  OIDC-only), email, display_name, external_provider,
  external_id, created_via, timestamps, totp_secret_encrypted,
  totp_enabled, totp_enabled_at, totp_recovery_codes_encrypted.
- **`sessions`** — id, user_id, token (UNIQUE), created_at,
  last_seen_at, expires_at.
- **`login_attempts`** — id, remote_ip, username, success,
  timestamp. Fed by the login rate-limiter. Purged at 24 h.
- **`totp_attempts`** — id, user_id, ip, success, attempted_at.
  Fed by the TOTP rate-limiter. Purged at 24 h.

### Proxy + WAF

- **`hosts`** — id, domain UNIQUE, target_group_id, tls_mode,
  tls_email, enabled, auth_required, lan_only (v1.3.18),
  true_detect_mode (v1.3.19, activated v1.3.29), tls_acme_ca_url
  (v1.3.7), tls_challenge (v1.3.7), tls_dns_provider (v1.3+),
  timestamps.
- **`target_groups`** — id, name UNIQUE, protocol, verify_tls,
  algorithm, health_check_*, preserve_host (v1.3.16), timestamps.
- **`targets`** — id, target_group_id, host, port, weight,
  enabled. UNIQUE(target_group_id, host, port).
- **`rules`** — id, host_id, priority, name, enabled,
  action_type, action_config (JSON), matchers_config (JSON).
  UNIQUE(host_id, priority).
- **`host_security`** — host_id PK, WAF and rate-limit fields.
  1:1 with hosts, CASCADE on delete.
- **`waf_exclusions`** — id, host_id, crs_rule_id, path_pattern,
  reason, enabled.
- **`waf_custom_rules`** — id, host_id, name, secrule text,
  enabled.
- **`cert_status`** — read-only mirror of Caddy-issued certs.
- **`host_manual_certs`** (v1.3.7) — manual cert uploads.
- **`dns_providers`** (v1.3+) — DNS-01 provider catalogue with
  encrypted credentials.

### Notifications

- **`notification_channels`** — id, name UNIQUE, type, enabled,
  config (JSON, secrets encrypted), template,
  rate_limit_per_minute.
- **`notification_rules`** — id, name, channel_id, event_type,
  filter_host_ids, filter_severities,
  throttle_window_seconds.
- **`notification_deliveries`** — id, rule_id (nullable on
  rule delete), channel_id (nullable), event_type, status,
  error_message, attempts, created_at, sent_at.
- **`push_subscriptions`** — id, user_id, endpoint, p256dh_key,
  auth_key, user_agent, UNIQUE(user_id, endpoint).

### Observability + audit

- **`log_entries`** — every ingested access / error / WAF audit /
  argos audit row. Indexed on timestamp + source + host_id +
  rule_id + status + waf_rule_id. Retention (v1.3.40.0) per
  source (`logs.retention.<source>_days`: access 7, error 30, audit
  90, waf_audit 30; `logs.retention_days` for anything else), `raw`
  kept only on the newest `logs.retention.raw_hours` (24) of access
  rows and emptied behind a watermark after that, and
  `logs.max_entries` (1,000,000 since v1.3.40.3) as a safety net,
  not the operating limit, checked through `MAX(id)-MIN(id)+1`
  before any `COUNT(*)`: the cap must stay above what retention
  keeps, or every purge pays a `COUNT(*)` over the table.

    !!! warning "Load-bearing by name (v1.3.38.4)"
        `idx_log_entries_status_ts`, `idx_log_entries_host_ts`,
        `idx_log_entries_source_ts` and `idx_log_entries_timestamp`
        are referenced by name with `INDEXED BY` in
        `internal/dashboard/queries.go` and `internal/db/logs.go`
        (the long-range paths). Renaming or dropping any of them
        breaks those queries **at runtime** (SQLite errors on an
        unknown index), not only the planner tests
        (`TestLongRangePlans`, `TestStatsLongPlans`). Any migration
        that touches them must update both files in the same
        commit.
- **`settings`** — key/value/updated_at. Runtime-tunable knobs
  live here. Surfaced state includes:
    - `appsec.disabled_scenarios` (v1.3.25) — CSV of canonical
      names the operator disabled in the panel.
    - `appsec.inbound_threshold` / `appsec.outbound_threshold`
      (v1.3.25) — operator-set CRS anomaly thresholds.
    - `appsec.scenarios.last_modified_at` /
      `appsec.tuning.last_modified_at` (v1.3.25) — sentinel
      mtime tracking.
    - `appsec.scenarios.drift_state` /
      `appsec.tuning.drift_state` (v1.3.27) — JSON snapshot
      from the drift detector's 60s tick. The `/api/security/
      drift` endpoint reads this on demand.
- **`backups`** — id, filename UNIQUE, size_bytes, sha256,
  kind ('manual' | 'scheduled' | 'orphan'), trigger_user_id
  (nullable on user delete), created_at, note.
- **`security_whitelist`** (v1.3.19) — operator-managed
  whitelist entries (scope: 'ip' | 'range', value, reason,
  created_at). Materialised into
  `/data/shared/argos-whitelist-entries.txt` for setup-appsec.sh.
- **`country_ban_expansions`** (v1.3.21) — id, country_code
  UNIQUE, decision_ids (JSON), cidr_count, reason, duration,
  created_at, created_by, mmdb_version_at_creation,
  **state** ('active' | 'drifted'; v1.3.33).
- **`country_expansion_jobs`** (v1.3.31) — async expansion
  worker tracking. id, country_code, state ('pending' |
  'running' | 'completed' | 'failed'), chunks_total /
  chunks_done / chunks_failed, cidr_committed,
  requested_count, duration, reason, error_message,
  created_at / started_at / completed_at, created_by.
  Indexed on (country_code, created_at DESC) and (state) for
  the per-country job list and the boot-time recovery sweep.
- **`schema_migrations`** — version PK, applied_at.

## go:embed frontend

The React SPA builds to `backend/static/` and embeds into the Go
binary:

```go
//go:embed index.html
//go:embed all:assets
var content embed.FS
```

The single binary serves the SPA at `/*` (any path that is not
`/api/*` or `/healthz`) falls through to `index.html` so client-
side routing works. No separate `nginx` container for static
assets.

Migrations embed similarly:

```go
//go:embed *.up.sql *.down.sql
var FS embed.FS
```

Adding a migration requires a rebuild; operators never interact
with SQL files directly.

## Out-of-band sentinels (`/data/shared/`)

Two-direction file-based exchange with the crowdsec container,
mounted as `/shared/` on its side. Either container reads or
writes; both sides treat these as plain text/JSON.

**Panel writes, setup-appsec.sh consumes** (the original
v1.3.19+ pattern):

- `argos-whitelist-entries.txt` — manual whitelist rows
- `argos-true-detect-hosts.txt` — pre-v1.3.29 hostname list
  (deprecated; replaced by argos-managed-profiles.yaml below)
- `argos-disabled-scenarios.txt` (v1.3.25) — canonical scenario
  names the operator disabled
- `argos-appsec-tuning.txt` (v1.3.25) — `inbound_threshold=`
  / `outbound_threshold=`
- `argos-managed-profiles.yaml` (v1.3.29) — full
  CrowdSec-profile YAML block; setup-appsec.sh splices it
  between `# >>>>> argos-managed: true_detect_mode hosts`
  markers in `/etc/crowdsec/profiles.yaml`

**setup-appsec.sh writes, panel consumes** (the v1.3.30
reverse-sentinel pattern):

- `argos-scenarios-index.json` — slimmed
  `{canonical_name: description}` map of CrowdSec's hub catalogue
  for the Scenarios tab tooltip enrichment

The reverse-sentinel pattern exists because `/etc/crowdsec/hub/
.index.json` is mode 0600 root-owned in the volume; the panel
runs as `nobody` (uid 65534) and cannot read it directly through
the read-only `/crowdsec-state` mount. setup-appsec.sh runs as
root inside crowdsec, parses with jq, emits the slimmed file
with default 0644 perms.

## Backup semantics

`VACUUM INTO <path>` produces a fully consistent SQLite file
snapshot without blocking writers on the live DB. The backup
manager wraps that with a tar.gz + SHA-256 + metadata.json
sidecar. Detailed flow: [Backups](../features/backups.md).

Restores work by extracting the archive on top of `/data` on
the next container boot via a marker file
(`/data/.restore_pending`). The marker is consumed on start; an
extract failure leaves the pre-restore DB in place.

## What NOT to do

- **Do not edit `argos.db` while the panel is running.** Use the
  API. Out-of-band writes bypass the audit log and may collide
  with in-flight transactions.
- **Do not restore a backup with a different `ARGOS_MASTER_KEY`.**
  Every encrypted setting (OIDC client_secret, SMTP password,
  Telegram bot token, VAPID private key, TOTP secrets, recovery
  codes) becomes unrecoverable. Keep the master key alongside
  backups — in a different vault, so a single leak does not lose
  both.
- **Do not run two argos containers against the same `/data`.**
  SQLite's WAL mode tolerates multiple readers (argos itself uses a
  read-only pool next to its writer) but argos assumes it is the
  only writer. A second writer will see
  `SQLITE_BUSY` storms and partial audit rows.

## Related

- [Components](components.md) — who writes what.
- [Backups](../features/backups.md) — operational backup flow.
- [Migrations README](https://github.com/cmos486/argos-edge/blob/main/backend/migrations/README.md) —
  runner invariants + adding migrations.
