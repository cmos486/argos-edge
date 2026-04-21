# Changelog

All notable changes to argos-edge are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-04-21

Safety-net release before the v1.1 cert-lifecycle push. Makes the
ACME directory URL configurable so development / debugging can
target Let's Encrypt staging without burning production rate
limits.

### Added

- **ACME CA toggle.** New `acme.ca_url` global setting (empty =
  Let's Encrypt production, matches pre-1.0.1 default). New
  per-host `tls_acme_ca_url` field for targeted overrides
  (**host form → Advanced**). New `ARGOS_ACME_CA_URL` env var for
  emergency ops-level override. Precedence: env > per-host >
  global > Caddy default. Full documentation in
  [Reverse proxy → ACME CA options](docs/features/reverse-proxy.md#acme-ca-options).
- **Settings → ACME CA section.** Radio with production / staging
  / custom URL; amber warning while staging is selected.
- **Unit tests** for `caddycfg.ResolveACMECAURL` and
  `caddycfg.ValidateACMECAURL` (4 precedence cases + 5 valid + 5
  invalid URL shapes).

### Changed

- `caddycfg.HostsToCaddyConfig` signature gains an `ACMEOpts`
  parameter (env URL + global URL). Callers outside `reconciler`
  need the extra argument; none known externally.
- `acmeIssuer` JSON now emits a `ca` field when resolution returns
  non-empty; omitted otherwise so LE-production behaviour is
  unchanged for untouched panels.
- `docs/features/reverse-proxy.md` clarifies `tls_mode=auto`
  uses DNS-01 via Cloudflare (the previous line mislabelled it
  HTTP-01).

### Database

- **Migration 021**: `hosts.tls_acme_ca_url TEXT NOT NULL DEFAULT ''`.
  Backwards-compatible on upgrade (default empty = inherit
  global = LE production). Rollback drops the column.

### Upgrade notes

No breaking changes for end users. `docker compose pull && up -d`;
the migration runs automatically. Existing hosts continue to use
LE production unless you visit **Settings → ACME CA** and pick a
different preset.

## [1.0.0] - 2026-04-20

First stable release. The panel has been through its full
feature scope (phases 0 through "post-features hardening" plus
docs) and the maintainer considers it production-ready for the
homelab use case it targets.

### Added

**Reverse proxy and routing.** Hosts with Let's Encrypt via Caddy,
target groups with four LB algorithms (round_robin / least_conn /
ip_hash / random), targets with weights, active + passive health
checks, per-host listener rules (forward / redirect /
fixed_response / block / rewrite) with priority-ordered matching
(`c6d85b5`, `3f4ffaa`, `4264a40`, phase 2 target groups).

**Local authentication.** Username + bcrypt cost-12 password +
server-side sessions backed by SQLite, rate-limit on failed
logins (5-in-5min → 30-min ban, persisted), idle + absolute
session timeouts with cached settings (`fe6b05c`, `b1b22d4`,
`634b58b`).

**2FA with TOTP.** RFC 6238, encrypted-at-rest secrets, 10
one-shot recovery codes, per-(user,ip) rate limit, regenerate
flow gated by password, break-glass CLI subcommand (`8083701`,
`488dac7`).

**OIDC SSO.** Authorization Code + PKCE (S256), pluggable for
any compliant provider (Google, Microsoft, Keycloak, Authentik,
Authelia documented in detail), auto-provisioning with email /
domain allowlist, opt-in email_verified enforcement (`d03f7fc`,
`6858364`).

**ForwardAuth.** Per-host `auth_required` flag, cookie
parent-domain support for cross-subdomain SSO, 30 s in-process
cache with eager eviction on logout, structured `X-Auth-*`
headers to the upstream (part of `d03f7fc`).

**Inline WAF.** Coraza + OWASP CRS through the CrowdSec AppSec
component, three runtime modes (detect / block / disabled) with
instant reconcile, per-host enable, paranoia 1-4, scoped
exclusions, free-form custom SecRule text (`cae1fa9`).

**CrowdSec integration.** Bouncer plugin at the edge polling LAPI
every 15 s, local detection scenarios, community blocklist, panel
UI for decisions with add/delete, status view, scenarios browser
(`e79e984`, `2b76957`, `1243ddf`).

**GeoIP enrichment.** DB-IP Lite country + ASN databases,
monthly refresh cron (day 5 at 03:00 UTC), lazy enrichment for
log rows + dashboard cards, country flags in UI (`a384e71`).

**Dashboard.** Four sections (overview, traffic, security, health)
with a 30-second client poll, sparkline traffic chart, attacks-by-
country world map, top offending IPs table (`3b2488e`, `7c5f870`,
`62e99aa`).

**Observability.** Unified `log_entries` store for caddy_access +
caddy_error + waf_audit + audit sources, filter API with status
expressions (`4xx`, `200-299`, CSV), regex path matching, SSE
tail, aggregate stats per window, timeseries bucketing, full
audit trail with `remote_ip` + `user_agent` on every auth event.

**Notifications.** Four channel types all implemented (webhook,
email, telegram, browser push), 16 event types, per-channel
token-bucket rate limit, per-rule throttle window with event dedup
(`f91c0c3`).

**Backups.** Scheduled cron (default 02:00 UTC daily) + manual,
`VACUUM INTO` snapshot + tar.gz archive with SHA-256 verification,
configurable retention, restore via UI / CLI / authed upload
endpoint, orphan reconcile on boot (`1707be8`, `c348f89`).

**Documentation portal.** 33 markdown pages covering landing,
getting-started, 5 workflow playbooks, 9 feature references, 4
architecture pages with mermaid diagrams, 4 operations pages,
4 flat reference pages. mkdocs-material theme, GitHub Actions
pipeline that builds strict and deploys to GitHub Pages on push
to main (`421832e` through `ec06f1e`).

**Two deployment modes.** `lan` (default, plain HTTP, LAN-only)
and `behind_caddy` (Caddy-fronted HTTPS, Secure cookies, HSTS +
CSP). Compose override for the latter (`a1561c4`).

### Changed

**Frontend code-split** — initial JS bundle cut from 1,082 KiB
to 215 KiB minified (`-80.1%`), with React.lazy boundaries on
every top-level route and `manualChunks` vendor splits for
charts / map / icons / dnd. Eliminated the Vite `>500 KiB`
warning (`56e4599`).

### Fixed / Security

**Timing parity in `auth.Authenticate`.** Unknown / OIDC-only /
wrong-password paths all burn the same bcrypt cycle so an attacker
cannot enumerate usernames via response-time (`affd78c`).

**Compare-and-swap for recovery code consumption.** Two concurrent
submissions of the same recovery code no longer both mint a
session; the loser retries against the post-CAS blob and either
finds the code already consumed or picks a different one
(`7bd3c28`).

**X-Real-IP spoof gated on panel mode.** `middleware.RealIP` and
`h.clientIP()` only trust the header in `behind_caddy` mode where
Caddy is the sole ingress. In `lan` mode the real socket peer is
used, so an attacker on the LAN cannot rotate IPs to defeat the
login rate limiter (`55884b3`).

**`safeReturnTo` rejects backslash + control chars.** Closed an
open-redirect bypass where `/\evil.com` would fool the
`HasPrefix("//")` check but browsers normalise `\` to `/`, crossing
origins on navigation. Also rejects `%5c` / `%5C` and ASCII
control bytes 0x00-0x1f + 0x7f (`94e3cb6`).

**Opt-in `email_verified` enforcement on OIDC.** New setting
`oidc.require_email_verified` (default false for backcompat);
when on, rejects id_tokens that lack the claim or send it false
BEFORE the allowlist check (`6858364`).

**Auth audit completeness.** `remote_ip` + `user_agent` now on
every authentication event (login success/failure,
rate_limited_login, login_totp_challenge, all totp events,
oidc_login_failed + oidc_login_success, logout). Two missing
events backfilled (`801fa1c`).

**Wiring fixes flagged by the internal sweep.**
`RateLimiter.Drop` called from `DeleteNotificationChannel` so
bucket state does not leak across channel recreate with same id
(`a1b7578`). `PurgeTOTPAttempts` wired into the retention cron
so the table stops growing unbounded (`3e9186c`).

### Infrastructure

**Test coverage push.** 45 new test entries across 6 previously
unteseted packages (auth, session, hardening, logs, notifications,
db). New tests include real-DB migration roundtrips, a CAS-race
suite, a timing-parity bound that caught the pre-fix regression
when tested against reverted source (`48f702f` through `7976a6c`).

**Static analysis clean.** `go vet` + `staticcheck` zero warnings
across the tree after a dead-code sweep that dropped 9 unreachable
helpers and marked 5 ambiguous ones with `TODO(kilian): dead?`
for later decision (`ee8ce16`).

**Code quality baseline.** `gofmt` applied to 20 files'
accumulated whitespace drift (`9a6fc99`); notification-channel
rate-limiter Drop wiring closed the latent bucket-leak noted in
the security audit.

**Migrations README.** Documented runner invariants, per-version
transactional apply, Go-hook semantics, the gap at `013`, and the
squash policy (not squashing at v1.0; revisit at >40 migrations
or a major version jump) (`9920a1d`).

**GitHub Actions docs deploy.** CI builds `mkdocs build --strict`
on every PR and deploys to `gh-pages` on push to main. First
push after this tag lights the portal up at
<https://cmos486.github.io/argos-edge/>.

### Known limitations

See [Known limitations](docs/release-notes/v1.0.0.md#known-limitations)
in the v1.0.0 release notes.

---

Commits referenced here are full-tree SHAs visible in `git log`.
Use `git show <sha>` to pull the specific change.

[1.0.0]: https://github.com/cmos486/argos-edge/releases/tag/v1.0.0
