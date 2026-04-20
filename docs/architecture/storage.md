# Storage

One SQLite file. WAL mode with `NORMAL` synchronous, foreign keys
on, 5-second busy timeout. `SetMaxOpenConns(1)` on the Go side so
writes always go through the same connection and contention stays
bounded.

## Why SQLite

Argos is single-writer by design: one panel instance, one Go
process, one admin. SQLite is the right fit:

- Zero-config. No Postgres container, no tuning pool, no network
  DB.
- Atomic backups via `VACUUM INTO`.
- WAL gives concurrent readers (log browser + dashboard polling
  the DB while the worker writes) without the writer blocking.
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
  goroutines write during heavy request traffic.

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
  tls_email, enabled, auth_required, timestamps.
- **`target_groups`** — id, name UNIQUE, protocol, verify_tls,
  algorithm, health_check_*, timestamps.
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
  rule_id + status + waf_rule_id. Retention via
  `logs.retention_days` + `logs.max_entries`.
- **`settings`** — key/value/updated_at. Runtime-tunable knobs
  live here.
- **`backups`** — id, filename UNIQUE, size_bytes, sha256,
  kind ('manual' | 'scheduled' | 'orphan'), trigger_user_id
  (nullable on user delete), created_at, note.
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
  SQLite's WAL mode tolerates multiple readers but argos assumes
  it is the only writer. A second writer will see
  `SQLITE_BUSY` storms and partial audit rows.

## Related

- [Components](components.md) — who writes what.
- [Backups](../features/backups.md) — operational backup flow.
- [Migrations README](https://github.com/cmos486/argos-edge/blob/main/backend/migrations/README.md) —
  runner invariants + adding migrations.
