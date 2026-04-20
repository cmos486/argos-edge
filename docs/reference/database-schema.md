# Database schema

One SQLite file at `/data/argos.db` in the `argos_data` volume.
WAL mode, `SetMaxOpenConns(1)`, foreign keys on.

This page summarises each table's purpose + key columns. The
authoritative source is the migration chain under
`backend/migrations/`. Schema policy and the runner contract live
in the [Migrations README](https://github.com/cmos486/argos-edge/blob/main/backend/migrations/README.md).

## Identity + auth

### `users`

One row per human with panel access. Can represent a local
password account, an OIDC-only account, or both (admin bootstrapped
locally who later binds an OIDC identity).

Key columns:

- `id` PK
- `username` UNIQUE
- `password_hash` — nullable for OIDC-only users
- `email`, `display_name`
- `external_provider`, `external_id` — OIDC sub binding
- `created_via` — `local` or `oidc`
- `totp_secret_encrypted`, `totp_enabled`, `totp_enabled_at`,
  `totp_recovery_codes_encrypted`
- `created_at`, `updated_at`, `last_login`

Partial UNIQUE index on `(external_provider, external_id)` so two
rows cannot claim the same OIDC sub.

### `sessions`

Server-side sessions. The `argos_session` cookie carries only the
opaque `token`; all state lives here.

Key columns:

- `token` UNIQUE
- `user_id` FK → users(id) ON DELETE CASCADE
- `created_at`, `last_seen_at`, `expires_at`

Indexes on `token`, `user_id`, `expires_at`.

### `login_attempts`

Fed by `LoginRateLimiter.Record()`. Purged at 24 h.

Key columns:

- `remote_ip`, `username`, `success`, `timestamp`

Index on `(remote_ip, timestamp DESC)` powers the rate-limit
query.

### `totp_attempts`

Same role for TOTP. Purged at 24 h by the retention cron (Fase 2
security fix wired this into `runPurge`).

Key columns:

- `user_id` FK, `ip`, `success`, `attempted_at`

Index on `(user_id, ip, attempted_at DESC)`.

## Proxy + WAF

### `hosts`

One public name per row. `target_group_id` is NOT NULL since
migration 005 — every host must dispatch to a group.

Key columns:

- `domain` UNIQUE
- `target_group_id` FK → target_groups(id) ON DELETE RESTRICT
- `tls_mode` (`auto` or `none`), `tls_email`
- `enabled`, `auth_required`
- `created_at`, `updated_at`

### `target_groups`

Pool definition.

Key columns:

- `name` UNIQUE
- `protocol` (`http` / `https`), `verify_tls`
- `algorithm` (`round_robin` / `least_conn` / `ip_hash` /
  `random`)
- `health_check_*` (enabled, path, method, expect_status,
  interval/timeout seconds, fails_to_unhealthy, passes_to_healthy)

### `targets`

Upstream endpoints within a group.

Key columns:

- `target_group_id` FK → target_groups(id) ON DELETE CASCADE
- `host`, `port`, `weight`, `enabled`

UNIQUE(`target_group_id`, `host`, `port`).

### `rules`

Per-host listener rules.

Key columns:

- `host_id` FK
- `priority` — int 1-50000 (enforced at the API; the DB-level
  CHECK was removed in migration 007 to support the reorder
  flow's temporary parking at priority+100000)
- `action_type` (`forward` / `redirect` / `fixed_response` /
  `block` / `rewrite`)
- `action_config` (JSON)
- `matchers_config` (JSON array of `{type, config}`)
- `enabled`

UNIQUE(`host_id`, `priority`).

### `host_security`

1:1 with hosts via PK `host_id` + ON DELETE CASCADE.

Key columns:

- `waf_enabled`, `waf_mode` (`detect` / `block`), `waf_paranoia`
  (1-4), `waf_block_status`, `waf_block_body`
- `rate_limit_enabled`, `rate_limit_requests`,
  `rate_limit_window_seconds`, `rate_limit_key`
  (`ip` / `header` / `global`), `rate_limit_header_name`,
  `rate_limit_status`

### `waf_exclusions`

Scoped CRS-rule-id + path-pattern exceptions.

Key columns:

- `host_id` FK, `crs_rule_id` (int > 0)
- `path_pattern` (empty = global exclusion)
- `reason`, `enabled`

UNIQUE(`host_id`, `crs_rule_id`, `path_pattern`).

### `waf_custom_rules`

Free-form Coraza SecRule text per host.

Key columns:

- `host_id` FK, `name`, `secrule`, `enabled`.

### `cert_status`

Read-only mirror of Caddy-issued certs, keyed by domain.

Key columns:

- `domain` PK, `issuer`, `not_after`, `last_checked_at`.

## Notifications

### `notification_channels`

Dispatch endpoints.

Key columns:

- `name` UNIQUE
- `type` (`webhook` / `email` / `telegram` / `browser_push`)
- `enabled`, `config` (JSON; secrets encrypted),
  `template`, `rate_limit_per_minute`

### `notification_rules`

Bind event types to channels.

Key columns:

- `channel_id` FK → notification_channels(id) ON DELETE CASCADE
- `event_type`, `filter_host_ids`, `filter_severities`,
  `throttle_window_seconds`, `enabled`

### `notification_deliveries`

Every dispatch attempt.

Key columns:

- `rule_id`, `channel_id` (both nullable → SET NULL on delete
  so history survives)
- `event_type`, `event_payload`, `rendered_payload`
- `status` (`pending` / `sent` / `failed` / `throttled` /
  `rate_limited`)
- `error_message`, `attempts`, `created_at`, `sent_at`

### `push_subscriptions`

Per-browser Web Push registrations.

Key columns:

- `user_id` FK, `endpoint`, `p256dh_key`, `auth_key`,
  `user_agent`

UNIQUE(`user_id`, `endpoint`).

## Observability + audit

### `log_entries`

Unified log store. Caddy's access log, Caddy's error log, Coraza
WAF audit entries, AND argos' own mutation audits all land here
keyed by `source`.

Key columns:

- `timestamp`, `source` (`caddy_access` / `caddy_error` / `audit`
  / `waf_audit`), `level`
- `host_id`, `host_domain`, `rule_id`
- `remote_ip`, `method`, `path`, `status`, `duration_ms`,
  `size_bytes`, `user_agent`, `upstream`
- `message`, `raw`
- WAF: `waf_rule_id`, `waf_rule_message`, `waf_severity`,
  `waf_anomaly_score`

Indexes on timestamp + source+ts + host_id+ts + rule_id+ts +
status+ts + waf_rule_id+ts.

Retention: `logs.retention_days` (default 30) + `logs.max_entries`
(default 500k cap).

### `settings`

Key/value/updated_at. Every runtime-tunable knob lives here.
Common prefixes:

- `logs.*` — retention, max_entries, offsets.
- `session.*` — timeouts.
- `backup.*` — enabled, schedule, retention_days, path.
- `crowdsec.*` — LAPI URL, poll interval, machine creds,
  bouncer API key.
- `oidc.*` — the full OIDC config surface (10 keys).
- `appsec.*` — mode + change-audit fields.
- `notifications.vapid_*` — VAPID keypair + contact email.
- `notifications.retention_days`, `.max_entries`.
- `panel.security_headers_strict`.

### `backups`

One row per tar.gz.

Key columns:

- `filename` UNIQUE
- `size_bytes`, `sha256`
- `kind` (`manual` / `scheduled` / `orphan`)
- `trigger_user_id` FK (nullable; SET NULL on user delete)
- `note`, `created_at`

### `schema_migrations`

Applied-migration set.

- `version` PK, `applied_at`

## Encrypted fields

The AES-GCM master key (`ARGOS_MASTER_KEY`) encrypts these string
columns at rest. Plaintext never touches disk.

| Table | Column | Type |
|---|---|---|
| `users` | `totp_secret_encrypted` | TOTP secret (base32) |
| `users` | `totp_recovery_codes_encrypted` | JSON blob of 10 codes |
| `settings` | `oidc.client_secret_encrypted` value | OIDC client secret |
| `notification_channels` | `config` → fields flagged `secret` | SMTP pw, Telegram token, etc. |

Ciphertext shape: `argos1:<base64(nonce || ciphertext || tag)>`.
Prefix lets callers round-trip either plaintext or ciphertext
through the same JSON fields without separate columns.

## Foreign key cascade matrix

| Child | Parent | ON DELETE |
|---|---|---|
| `sessions.user_id` | `users.id` | CASCADE |
| `hosts.target_group_id` | `target_groups.id` | RESTRICT |
| `targets.target_group_id` | `target_groups.id` | CASCADE |
| `rules.host_id` | `hosts.id` | CASCADE |
| `host_security.host_id` | `hosts.id` | CASCADE |
| `waf_exclusions.host_id` | `hosts.id` | CASCADE |
| `waf_custom_rules.host_id` | `hosts.id` | CASCADE |
| `log_entries.host_id` | `hosts.id` | SET NULL |
| `log_entries.rule_id` | `rules.id` | SET NULL |
| `notification_rules.channel_id` | `notification_channels.id` | CASCADE |
| `notification_deliveries.rule_id` | `notification_rules.id` | SET NULL |
| `notification_deliveries.channel_id` | `notification_channels.id` | SET NULL |
| `push_subscriptions.user_id` | `users.id` | CASCADE |
| `backups.trigger_user_id` | `users.id` | SET NULL |
| `totp_attempts.user_id` | `users.id` | CASCADE |

Pattern: dependent-configuration rows CASCADE; historic / audit
rows SET NULL so history survives a delete.

## Related

- [Storage](../architecture/storage.md) — architecture-level.
- [Migrations README](https://github.com/cmos486/argos-edge/blob/main/backend/migrations/README.md)
  — runner semantics.
- [Backups](../features/backups.md) — backup format + restore.
