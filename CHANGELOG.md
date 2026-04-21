# Changelog

All notable changes to argos-edge are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-04-21

Docs-only patch release. Closes the persistence audit raised
during v1.1.0 ship prep.

### Added

- **New operations page: [Persistence](docs/operations/persistence.md)**.
  Consolidates the storage story in one place: complete volume
  matrix (8 volumes × backup scope × loss impact × recovery
  path), backup-scope breakdown, step-by-step DR checklist,
  volume lifecycle operations (inspect / size / move / reset),
  filesystem-level integrity verification patterns, and a
  bind-mount production deployment guide with a full override
  template.
- **Bind-mount production layout section**. Covers the common
  case of replacing named volumes with host paths so existing
  filesystem-level backup tools (restic / borg / duplicity /
  ZFS snapshots) can operate on argos data directly. Includes
  the migration recipe for switching from named volumes to bind
  mounts on a running stack.
- **Rationale for `name:` override on volumes in `multi-instances.md`**.
  Explains why the shipped compose hardcodes volume names
  (accidental project-name changes must not move data;
  tooling predictability) and the trade-off (second instance
  requires a deliberate override YAML, not just `-p`).
- **Integrity verification patterns** in the new persistence page:
  sha256 baseline + verify commands, a ready-to-drop-in cron
  script for `caddy_manual_certs` drift detection, ZFS/Btrfs
  snapshot notes.

### Not changed

No code, no schema, no compose file changes. Pure documentation.
Standard upgrade is `git pull` + `docker compose up -d`; nothing
in the running stack changes.

## [1.1.0] - 2026-04-21

Minor feature release. Focus on certificate lifecycle: three ACME
challenge types, enriched renewal visibility, and full import
support for operator-owned certificates including disaster-recovery
materialisation on boot. Plus the navbar / layout refinements and
the Security / Logs / Settings documentation pages that landed
incrementally since v1.0.

### Added

- **ACME challenge selector** — new per-host `tls_challenge` field
  supporting `dns` (default, Cloudflare DNS-01 — unchanged from
  v1.0), `http` (HTTP-01 on :80), `tls-alpn` (TLS-ALPN-01 on
  :443). Host form gains a radio + amber reachability warning for
  the port-dependent challenges. See
  [Reverse proxy → TLS challenges](docs/features/reverse-proxy.md#tls-challenges).
- **Auto-renewal UI** — `/certs` (now at `/certificates`) is
  enriched with status badges (`ok` / `warning` / `critical` /
  `expired` / `unknown`), days-left column, last Caddy-error event
  (green/red dot + deep-link to filtered logs), next renewal
  estimate, and a **Renew now** button that re-pushes the Caddy
  config so certmagic re-evaluates every cert.
- **Import own certificates (Feature 5)** — new **Certificates →
  Imported tab** with an **Import certificate** modal. Upload
  cert + key + optional chain; argos validates (cert/key match,
  domain covered including wildcards, lifetime, chain well-formed),
  encrypts the key with `ARGOS_MASTER_KEY`, writes files to the
  new `caddy_manual_certs` volume, and flips the host to
  `tls_mode=manual` atomically. Host edit modal shows a read-only
  summary card for manual hosts plus a link to the Certificates
  page. Full docs at
  [Manual certificates](docs/features/manual-certs.md) and
  [Import own cert](docs/workflows/import-own-cert.md).
- **Manual cert DR reconciler** — on panel boot, after migrations
  and before the first Caddy reconcile, every `host_manual_certs`
  row is checked against the shared volume. Missing `.crt` / `.key`
  files are decrypted from the DB and materialised on disk. Makes
  the argos backup tarball (DB only) a self-contained DR unit for
  manual certs — `caddy_manual_certs` does not need out-of-band
  replication as long as `ARGOS_MASTER_KEY` is kept safe.
- **`manual_cert_expiring_soon` notification event** — daily cron
  fires at 30 / 14 / 7 / 1 days before expiry for each manual
  cert. Wire a notification rule to get a reminder before the
  cert lapses (manual certs have no auto-renewal by design).
- **ACME CA toggle** (from v1.0.1, included in this release) —
  global `acme.ca_url` setting + per-host `tls_acme_ca_url`
  override + `ARGOS_ACME_CA_URL` env var. Switch the whole panel
  or one host to LE staging for development without burning
  production rate limits.
- **Cert troubleshooting operations page** —
  [docs/operations/cert-troubleshooting.md](docs/operations/cert-troubleshooting.md)
  walks through the common failure modes per challenge type, rate
  limits, and when to use **Renew now** vs restoring from a
  backup.
- **Security overview, Logs browser, Settings** feature docs —
  three new pages under docs/features/ covering `/security`,
  `/logs`, and `/settings`.
- **GeoIP status card** in System → shows loaded DB versions, size,
  last refresh, next refresh, and a manual Refresh now button
  (from v1.0.x).

### Changed

- **Certificates page**: renamed from `/certs` to `/certificates`,
  split into `Active` / `Imported` tabs. `/certs` route redirects
  to `/certificates` for external-link compatibility.
- **Host update API**: `tls_mode` validator now accepts `manual`.
  Round-tripping a manual-mode host no longer errors. Direct flip
  auto/none → manual without an upload is rejected with a clear
  message pointing at the import flow. Reverse flip (manual →
  auto/none) cascades cleanup of the manual cert row + files.
- **Navbar / layout**: always-on hamburger, status pills (AppSec
  always visible, LAN-mode conditional), content width cap at
  1400 px, bigger logo, relative-timestamp component used across
  all list views.
- **Caddy config generation**: `acmeIssuer` emits a `ca` field when
  resolution returns non-empty (for staging / custom CA); omitted
  otherwise to preserve pre-1.0.1 behaviour.

### Database

- **Migration 021**: `hosts.tls_acme_ca_url TEXT NOT NULL DEFAULT ''`.
- **Migration 022**: `hosts.tls_challenge TEXT NOT NULL DEFAULT 'dns'`
  with CHECK constraint.
- **Migration 023** (Go hook): creates `host_manual_certs` table
  (host_id, cert_pem, key_pem_encrypted, chain_pem, not_after,
  not_before, sans, fingerprint, uploaded_at, uploaded_by) and
  extends `hosts.tls_mode` CHECK to accept `'manual'`. Uses the
  SQLite `writable_schema` pattern to update the CHECK in place
  without a full table rebuild.

All migrations are additive and roll forward cleanly from v1.0.

### Volumes

- **New**: `caddy_manual_certs` (host-side name:
  `argos_caddy_manual_certs`) shared read-write into argos-panel
  and read-only into argos-caddy. Panel writes uploaded cert + key
  files here; Caddy reads them via `tls.certificates.load_files`.

Operators running a second instance via the
[multi-instances override](docs/operations/running-multiple-instances.md)
must rename this volume alongside the others to avoid cross-stack
collision — the override template is updated accordingly.

### Documentation

- Installation Volumes table: listed 3 of the 8 volumes; rewritten
  to cover all 8 with backup-scope + "lose it and what happens"
  columns.
- `ARGOS_MASTER_KEY` is-part-of-your-backup callout added to
  installation, upgrading, and restore workflows.
- `docker compose down -v` danger callout added to upgrading +
  restore workflows (previously only in installation).

### Upgrade notes

Standard upgrade — schema migrations run automatically on boot,
all backwards-compatible:

```bash
cd argos-edge
git fetch --tags
git pull
docker compose pull
docker compose up -d
```

Existing `tls_mode=auto` hosts keep DNS-01 via Cloudflare as the
default challenge (migration 022 seeds every row with
`tls_challenge='dns'`). No action required unless you want to
switch a host to HTTP-01 / TLS-ALPN-01.

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
