# Tuning

Day-two knobs. Start with defaults; only tune once you have data
pointing at a specific problem.

## Session timeouts

Two settings govern how long a login stays valid:

- `session.absolute_timeout_hours` — upper bound on a session's
  lifetime regardless of activity. Default `168` (7 days).
- `session.idle_timeout_hours` — auto-logout if the session has
  been idle for this long. Default `24`.

Tuning guide:

| Scenario | Absolute | Idle |
|---|---|---|
| Shared workstation | 8 | 1 |
| Single-operator homelab | 168 | 24 |
| Panel-behind-SSO-only | 720 | 168 |

The idle check respects throttle: `last_seen_at` updates only
every 5 minutes to avoid a write per request.

Changes take effect on the next login; already-issued sessions
keep the cookie they were minted with.

## Login rate limit

Hardcoded in `internal/hardening/ratelimit.go`:

- 5 fails in 5 min → 30 min ban per IP.
- Ban persisted in `login_attempts` (survives restart).
- Trusted proxy (`X-Real-IP`) only honored in `behind_caddy` mode.

There is no runtime knob. To change, edit the constants and
rebuild. The defaults are deliberately aggressive — a homelab
admin should not be trying 6 passwords in 5 minutes.

## TOTP rate limit

Similar, also hardcoded:

- 5 fails in 15 min → 30 min lockout per `(user_id, ip)`.

## Log retention

Two controls:

- `logs.retention_days` — drop rows older than N days. Default
  `30`.
- `logs.max_entries` — after retention, trim to at most N rows
  (oldest first). Default `500000`.

For a busy public host, 500k can cover about a week; for a
homelab with 5 hosts it is more like months. Raise the cap if
forensics matter; lower retention if disk is tight. The retention
cron runs every 6 h.

## WAF tuning

### Paranoia level

Per-host, values 1-4. See [WAF](../features/waf.md) for the
scale. Default `1`. Most homelabs never move past 1.

Move to 2 if:

- Log analysis shows repeated successful probes matching CRS
  rules at higher paranoia levels.
- The host handles payment / auth / sensitive data and you are
  willing to tune false positives.

### Exclusions vs paranoia

If a specific rule produces false positives, scope an exclusion
(same page, **Exclusions → New**):

- Path pattern: the endpoint that trips it (`^/api/upload$`).
- Rule ID: the CRS rule number from the WAF audit log.
- Reason: why the exclusion exists (for the audit trail).

Prefer many narrow exclusions over disabling a whole rule range.

### Custom rules

Write Coraza SecRule text for arbitrary logic. ID range 9xxxxx
to avoid collision with the CRS namespace. Syntax errors are
caught at reconcile time.

## Rate limit per host

`host_security.rate_limit_*` fields. Start permissive:

- `100 / 60` (100 rpm) is a safe starting point for a UI host.
- `1000 / 60` for a public API.

Tighten once you see sustained 429s in `caddy_access` logs that
match legit clients — that usually means the limit is too low,
not that the client is abusive.

Key strategy:

- `ip` (default) — per-client. Right for most cases.
- `header` — per value of a named header. Use for per-API-key
  quotas where each client sends an identifying header.
- `global` — one bucket total. Use when you want a maximum
  request rate for the whole host regardless of client.

## Backup retention

- `backup.retention_days` — how long to keep archives on disk.
  Default `14`.

Tuning depends on:

- **Disk** — each archive is ~10-50 MB for a homelab panel.
  14 days × 50 MB = 700 MB; reasonable.
- **RPO tolerance** — how far back you might want to restore from.
  Default 14 d is "two weeks of daily backups" which catches most
  "I broke something yesterday" cases.

No off-site replication. If you need that, mirror
`/data/backups/` with rclone/borg/rsync as a sidecar.

## Notification rate limits

Per-channel, `rate_limit_per_minute`:

- Low enough to avoid flooding the channel on an attack storm:
  a webhook-to-Slack with `10/min` is reasonable; most humans do
  not want more than that.
- Too low and legitimate events get `rate_limited` in the
  Deliveries tab. Watch for non-zero `rate_limited` counts;
  bump if sustained.

Per-rule `throttle_window_seconds` deduplicates the same event on
the same rule within the window. Set to the "how often do I want
to be pinged about the same thing" value:

| Event | Throttle |
|---|---|
| `cert_renewal_failed` | 0 (fire every time) |
| `backup_failed` | 0 |
| `waf_attack_burst` | 300 (5 min) |
| `target_unhealthy` | 300 |
| `login_failed` | 3600 (1 hour) |

## ACME CA for development

By default every `tls_mode=auto` host issues against **Let's
Encrypt production**. Production has a hard rate limit: **50
certs per registered domain per week**, and a botched issuance
loop can burn it in minutes. Two ways to avoid that during
development and debugging:

### Global staging toggle

**Settings → ACME CA → Let's Encrypt staging** switches every
auto-host onto the staging directory
(`https://acme-staging-v02.api.letsencrypt.org/directory`). Rate
limits are ~30× higher, but the certs chain to an untrusted root
so browsers will warn. Fine for a dev panel; never for production.

Do NOT leave this on for a panel users actually visit. The
Settings UI shows an amber warning while staging is selected
precisely to nudge you back.

### Per-host override (the usual case)

Flip the global to production, then override one host via **host
form → Advanced → ACME CA URL override** with the staging
directory. Only that host gets the untrusted cert; the rest of the
panel keeps its LE production certs untouched.

Useful when:

- Reproducing an issuance failure on one domain without impacting
  the others.
- Testing a brand-new host before committing production rate
  limits.

Clearing the field (or flipping `tls_mode` to `none` and back)
removes the override; the host returns to the global on the next
reconcile.

### Env var emergency override

`ARGOS_ACME_CA_URL` on the panel container overrides both. Survives
DB restores, Caddy restarts, and misbehaving UIs — set it when you
need a guaranteed CA for every auto-host regardless of DB state.
See [env vars](../reference/env-vars.md#argos_acme_ca_url).

## Reconciler tick

The panel re-pushes the Caddy config on every mutation. There is
no tunable tick; changes propagate within a second of save. If
you see stale config, look at `docker compose logs argos | grep
reconcile` for errors.

## Caddy admin API

Running on `:2019`, docker-bridge-only. NEVER publish this port.
A compromise there is a full edge reconfiguration.

## Sweeper intervals

In-memory garbage collectors with defaults:

- **OIDC PendingStore** — every TTL/2 (5 min for the 10-min TTL).
- **TOTP ChallengeStore** — every TTL/2 (2.5 min for the 5-min
  TTL).
- **ForwardAuth cache** — every 30 s.

These are internal consts; operators do not tune them.

## Related

- [Monitoring](monitoring.md) — what the tuning is optimising for.
- [Troubleshooting](troubleshooting.md) — when tuning did not
  help.
- [Env vars](../reference/env-vars.md) — bootstrap-level knobs.
