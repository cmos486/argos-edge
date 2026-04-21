# v1.3 Feature — DNS providers expansion

Technical analysis, no implementation.

Baseline: HEAD `34f682d` (tag `v1.2.0`). Current state:

- Caddy Dockerfile at `caddy/Dockerfile:17` builds with exactly one
  DNS provider: `github.com/caddy-dns/cloudflare`.
- Panel config generator at `backend/internal/caddycfg/caddycfg.go:1005-1008`
  hardcodes `Name: "cloudflare"` and `APIToken: "{env.CLOUDFLARE_API_TOKEN}"`.
- `hosts.tls_challenge` column (migration 022) takes `dns | http | tls-alpn`;
  the `dns` branch always means Cloudflare today.
- The Cloudflare token flows via `.env` → `docker-compose.yml`
  `environment: CLOUDFLARE_API_TOKEN=${CLOUDFLARE_API_TOKEN:-}` → the
  caddy container → Caddy reads `{env.CLOUDFLARE_API_TOKEN}` at `/load`
  time. Panel never sees the token value.
- Existing encryption pattern: `crypto.Cipher` (AES-GCM, master key
  from `ARGOS_MASTER_KEY`, `argos1:` prefix). Already used for OIDC
  client secrets, SMTP passwords, webhook auth headers, VAPID private
  key, manual-cert private keys.

---

## 1. caddy-dns catalogue (ranked by stars)

Top 25 repos under `github.com/caddy-dns/*` as of 2026-04-21:

| # | Module | Stars | Last commit | License | Notes |
|---|--------|-------|------------|---------|-------|
| 1 | cloudflare | 887 | 2026-03-23 | MIT | Already wired |
| 2 | porkbun | 91 | 2025-05-09 | MIT | Popular indie registrar |
| 3 | duckdns | 88 | 2025-04-19 | — | Dynamic DNS + free certs combo |
| 4 | route53 | 75 | 2025-11-21 | MIT | AWS |
| 5 | acmedns | 66 | 2025-09-26 | MIT | CNAME-delegation, self-host or public |
| 6 | alidns | 65 | 2026-02-13 | MIT | Alibaba Cloud |
| 7 | hetzner | 64 | 2026-04-16 | MIT | **v2.0.0 2026-04-04**, EU popular |
| 8 | namecheap | 62 | 2025-12-03 | **unspec** | License missing from repo |
| 9 | digitalocean | 53 | 2025-06-06 | — | No formal releases, module works |
| 10 | desec | 41 | 2026-02-10 | MIT | Privacy-oriented EU |
| 11 | ovh | 39 | 2025-05-19 | MIT | EU popular |
| 12 | dnspod | 34 | 2026-03-25 | MIT | Tencent / CN |
| 13 | tencentcloud | 32 | 2026-02-23 | MIT | CN |
| 14 | ionos | 28 | 2025-09-14 | — | EU hosting |
| 15 | netcup | 26 | 2025-06-11 | — | DE |
| 16 | powerdns | 26 | 2025-10-18 | — | Self-hosted PowerDNS |
| 17 | rfc2136 | 26 | 2025-05-02 | — | Generic TSIG-based dynamic updates |
| 18 | inwx | 21 | 2025-11-27 | — | EU registrar |
| 19 | gandi | 18 | 2025-07-15 | MIT | EU registrar, bearer_token API |
| 20 | googleclouddns | 17 | 2025-06-25 | — | GCP |
| 21 | bunny | 16 | 2025-05-25 | — | Bunny.net |
| 22 | netlify | 14 | 2025-10-12 | — | |
| 23 | godaddy | 13 | 2026-03-09 | — | |
| 24 | google-domains | 12 | 2023-02-09 | — | **Dead: service sunset** |
| 25 | hetzner (repo ranks differ) | see #7 | | | |

### Maintenance health cut

"Last commit ≤ 6 months" (since 2025-10-21) screens out abandoned
providers:

- **Active (≤6mo)**: cloudflare, alidns, hetzner, desec, dnspod,
  tencentcloud, godaddy, netlify, powerdns (Oct)
- **Recent (6-12mo)**: route53 (Nov), namecheap (Dec), acmedns (Sep),
  digitalocean (Jun), ovh (May), porkbun (May), duckdns (Apr),
  gandi (Jul), bunny (May), netcup (Jun), googleclouddns (Jun),
  rfc2136 (May), inwx (Nov), ionos (Sep)
- **Stale (>12mo)**: google-domains (service is dead anyway)

The "recent" tier is fine — caddy-dns modules are thin wrappers
around `libdns/*`, which handles the churn. A module with no commits
in 9 months is usually not abandoned; it just has no bugs.

### Recommended "top N" to ship with v1.3

**Tier 1 (must-have, 5 providers):**

1. **cloudflare** (already there — do not regress)
2. **route53** — AWS ubiquity, well-maintained
3. **digitalocean** — homelab-popular, simple auth
4. **hetzner** — EU homelab popular, v2.0.0 just shipped
5. **porkbun** — indie registrar with a real API, cheap for homelabs

**Tier 2 (stretch, pick 3-4 based on effort):**

6. **gandi** — EU registrar popularity
7. **desec** — privacy-oriented, frequent in this audience
8. **ovh** — EU, larger user base
9. **duckdns** — dynamic DNS use case
10. **acmedns** — covers "my registrar has no API but I can CNAME
    `_acme-challenge`" — a clean workaround for unsupported providers

**Skip for v1.3:**

- **namecheap** — unclear license, concerning for redistribution.
- **alidns / dnspod / tencentcloud** — CN-specific, low homelab signal,
  can add later if asked.
- **google-domains** — service sunset.
- **rfc2136** — niche, config is TSIG key material that needs a file
  not a string; doesn't fit the "paste token into settings page" UX.

---

## 2. Credential shapes per provider

Each provider takes a different auth shape. Summary of the Tier 1 +
Tier 2 candidates:

| Provider | Field(s) (JSON key) | Env var convention | Notes |
|---|---|---|---|
| cloudflare | `api_token` | `CLOUDFLARE_API_TOKEN` | 1 field; Zone:DNS:Edit scope |
| route53 | `access_key_id`, `secret_access_key`, `region?`, `session_token?`, `profile?` | `AWS_*` | 2 required + 3 optional; region defaults us-east-1 |
| digitalocean | `auth_token` | custom | 1 field |
| hetzner (v2) | `api_token` | custom | 1 field |
| porkbun | `api_key`, `api_secret_key` | custom | 2 fields |
| gandi | `bearer_token` | `GANDI_BEARER_TOKEN` | 1 field (PAT; API key deprecated) |
| desec | `token` | custom | 1 field |
| ovh | `endpoint`, `application_key`, `application_secret`, `consumer_key` | `OVH_*` | 4 required; endpoint is `ovh-eu` / `ovh-us` / etc |
| duckdns | `api_token`, `override_domain?`, `resolver?` | `DUCKDNS_API_TOKEN` | 1 required |
| acmedns | `username`, `password`, `subdomain`, `server_url`, `fulldomain?` | — | 4-5 fields, plus DNS CNAME setup by user |

All providers surveyed accept `{env.VAR}` placeholder substitution in
the JSON config values. **None** offer file-based secret loading;
Caddy's convention is strictly env-var interpolation.

### Implications for the panel data model

- Fixed columns per provider are infeasible: 1 to 5 fields, heterogeneous
  names, some with optional fields that change with provider version.
- A JSON blob per provider, encrypted as a whole, fits naturally.
  Field names live in the panel's provider catalog metadata (static
  Go struct); the blob is `{"api_token": "..."}` or
  `{"access_key_id": "...", "secret_access_key": "...", "region": "eu-west-1"}`.

---

## 3. Architecture — DB schema

### Recommendation: **Option A (dedicated table)**, with per-provider JSON blob.

```sql
-- Migration 024
CREATE TABLE dns_providers (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    name                  TEXT NOT NULL UNIQUE
        CHECK (name IN ('cloudflare', 'route53', 'digitalocean',
                        'hetzner', 'porkbun', 'gandi', 'desec',
                        'ovh', 'duckdns', 'acmedns')),
    enabled               BOOLEAN NOT NULL DEFAULT 0,
    credentials_encrypted BLOB,           -- argos1: JSON blob, null allowed when disabled
    updated_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Pre-populate cloudflare row on migration so the UI shows all
-- supported providers even when nothing is configured yet. enabled=0
-- by default; operator flips it in Settings.
INSERT INTO dns_providers (name, enabled) VALUES
    ('cloudflare',   0),
    ('route53',      0),
    ('digitalocean', 0),
    ('hetzner',      0),
    ('porkbun',      0),
    ('gandi',        0),
    ('desec',        0),
    ('ovh',          0),
    ('duckdns',      0),
    ('acmedns',      0);
```

### Why not Option B (settings key-value)

The existing `settings` table is flat `(key, value)` (see
`migrations/008_logs_and_settings.up.sql:36`). It is fine for scalars
like `logs.retention_days`. For DNS providers:

- We need per-provider atomicity: all fields of `route53` get updated
  together or not at all. With flat settings, you would write
  `dns.route53.access_key_id`, `dns.route53.secret_access_key`,
  `dns.route53.region` as three rows; a mid-write crash leaves a
  partial config.
- We need enable/disable per provider as a first-class toggle.
- We need `ListSettingsByPrefix`-style lookups to iterate providers
  at reconcile time — possible with flat settings but awkward, and
  the whitelist validator machinery (`api/settings.go:20-34`) does not
  compose well with "value is an encrypted JSON blob".

Flat settings works for one-of-each scalars, not for a catalogue of
polymorphic record types.

### Why not Option C (per-provider columns)

- Schema grows with every new provider; every migration needs a CHECK
  rewrite dance (see migration 023's `writable_schema` trick). Adding
  a provider should be a Go-code change, not a DB migration.
- Optional fields (route53 `profile`, ovh `endpoint`) end up as
  always-null columns for every other provider. Waste.

### Host-side change

Add one column to `hosts`:

```sql
-- Migration 025
ALTER TABLE hosts
  ADD COLUMN tls_dns_provider TEXT NOT NULL DEFAULT 'cloudflare';
```

No CHECK. Validation lives in the API layer against the
`dns_providers` catalogue — a value like `foo` is rejected at
write time, not by the DB. Reasons:

- The enum grows over time; CHECK requires writable_schema to extend,
  which is painful.
- API-layer validation also needs to check that the chosen provider
  is currently **enabled** in `dns_providers.enabled=1`. That's a
  JOIN, not a CHECK. Keep all rules in one place (the API handler).

Default `cloudflare` preserves behaviour for existing rows where
`tls_challenge='dns'` was assumed to mean Cloudflare.

### Why not extend the enum (`dns-cloudflare`, `dns-route53`, ...)

- The challenge type and the provider are orthogonal concerns. DNS-01
  vs HTTP-01 is "how does the CA validate". Cloudflare vs Route53 is
  "which DNS API does Caddy call". Conflating them into one column
  muddies the semantic.
- Forces the `tls_challenge` CHECK to be rewritten for every new
  provider.
- Forces the host form UI to fan out from 3 radios to 3 + N radios,
  most of which are "dns-something" and crowd the form.

---

## 4. Architecture — credentials pipeline to Caddy (the critical decision)

**This is the deepest design question of the feature.** Caddy reads
credentials from env vars at `/load` time via the `{env.VAR}`
placeholder. There is no `load_secret` directive, no
`{file.<path>}` placeholder, no way to push a secret after-the-fact
through the admin API except by re-sending the full config.

### Option 1 — keep the env-var pattern, ADD vars per provider

- Panel still stores credentials in DB (encrypted).
- On settings save, panel rewrites a `/run/secrets/dns.env` file
  inside the caddy container via a shared volume, then restarts
  the caddy container so it re-reads `env_file`.
- The generated JSON keeps using `{env.ROUTE53_ACCESS_KEY_ID}` etc.

**Pros:** minimal change to the existing pattern; keeps secrets out
of the /load payload.

**Cons:** container restart drops open connections. For a homelab
edge gateway that is tolerable but visible. Also, `env_file` is
read only at container start — a SIGHUP or `caddy reload` does not
pick up new env; a full container restart is required. Plus there's
no clean way for the panel to drop a file inside the caddy container
that the caddy container also reads — we'd need a new shared volume
specifically for this, which adds a volume, a permission puzzle,
and a reconciler bootstrap concern.

### Option 2 — inline decrypted values into the /load JSON

- Panel decrypts credentials on every reconcile (same lifecycle as
  OIDC client secret handling today).
- Generated JSON embeds literal values in the `dns.provider` stanza:
  `{"api_token": "actual-secret-value"}` not `{"api_token": "{env.X}"}`.
- Caddy receives the full config with secrets inline on `/load`;
  stores it in its in-memory config; never writes the secret to disk
  (caddy's data dir does not persist the /load payload).

**Pros:**

- No container restart on credential rotation. `caddy reload` via the
  admin API picks up new creds on the next reconcile.
- One pipeline: already-decrypted secrets flow through the same path
  as every other setting. No new volume, no `env_file` rewrite, no
  SIGHUP.
- Works identically for all ~95 caddy-dns providers because the
  placeholder mechanism is common to all of them — by using literal
  values instead, we skip the placeholder question entirely.

**Cons:**

- Secrets appear in `GET /config/` responses from Caddy's admin API.
  Mitigation: the admin API listens on `0.0.0.0:2019` inside the
  docker network but is not published on the host (see
  `docker-compose.yml` — no port mapping for caddy admin). It is
  reachable only from the panel container and an attacker on the
  docker network. Already our trust boundary for the bouncer API
  key placeholder today.
- Secrets live briefly in the panel process memory during reconcile.
  Already true for every other encrypted secret (OIDC, SMTP, VAPID).
- Caddy logs at DEBUG level include full config snippets. Mitigation:
  we already run caddy at INFO in production (see the `errors_file`
  logger `Level: "INFO"` in `caddycfg.go:278`); DEBUG would need to
  be turned on explicitly.

### Option 3 — hybrid (env for Cloudflare legacy, inline for new)

Keep `{env.CLOUDFLARE_API_TOKEN}` for the existing Cloudflare flow
(preserving the "token stays in compose, never in DB" promise the
current docs make), add inline for every new provider.

**Pros:** no behavioural regression for existing Cloudflare users.

**Cons:** two pipelines to maintain, two docs explanations, two
trust-boundary stories. Existing Cloudflare users can easily be
migrated: the Settings page reads the env var on first load and
offers to store it in the DB for unified handling (then `.env` can
be emptied).

### Recommendation: **Option 2** (inline on /load), with a one-time
migration notice for Cloudflare users.

Rationale:

- Container restart on every credential rotation (Option 1) is a
  real UX regression, not a minor footnote.
- The trust boundary around Caddy's admin API is already our
  assumption for crowdsec bouncer key, panel-to-caddy reconcile,
  and everything else. Adding DNS provider credentials to the same
  set does not change the threat model.
- One pipeline to test, one pipeline to document.
- Credential rotation becomes hot: save in Settings → reconcile
  → `caddy reload` → new order uses new token. No container dance.

The one operational note: `GET /config/...` from a shell on the
caddy container exposes the plaintext creds. Update
`docs/operations/persistence.md` and `ARCHITECTURE.md` to make this
explicit. This is information, not a new risk — the same shell
could read `env | grep CLOUDFLARE` today.

### Transition plan for existing Cloudflare users

1. On panel boot (v1.3.0), if `CLOUDFLARE_API_TOKEN` env is set AND
   no row exists in `dns_providers` for cloudflare with credentials,
   create one with `enabled=1` and the env value encrypted in.
2. Emit a one-time log line: `dns_provider: imported CLOUDFLARE_API_TOKEN
   into DB; you may remove it from .env at your next restart`.
3. Caddy config generator prefers DB creds over `{env.X}` — the env
   placeholder is emitted ONLY when the DB row is missing / disabled
   (legacy compatibility path for users who somehow land on v1.3
   without running the import).
4. Docs in `docs/features/reverse-proxy.md` updated: "Cloudflare
   credentials now live in Settings → DNS providers; .env token is
   deprecated."

---

## 5. Architecture — xcaddy build

Options considered:

**Bundle everything at build time** (recommended).

```dockerfile
RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/caddy-dns/route53 \
    --with github.com/caddy-dns/digitalocean \
    --with github.com/caddy-dns/hetzner/v2 \
    --with github.com/caddy-dns/porkbun \
    --with github.com/caddy-dns/gandi \
    --with github.com/caddy-dns/desec \
    --with github.com/caddy-dns/ovh \
    --with github.com/caddy-dns/duckdns \
    --with github.com/caddy-dns/acmedns \
    --with github.com/corazawaf/coraza-caddy/v2@v2.5.0 \
    # ... (unchanged)
```

Size impact: each caddy-dns module is a thin wrapper around libdns
plus the vendor SDK (AWS SDK for route53 is the biggest at ~15MB
compressed, hetzner/porkbun/desec/gandi are <1MB). Total estimated
image growth: ~30MB compressed on top of the current ~80MB caddy
image. Acceptable for a self-hosted tool.

- **Runtime skipping is not possible** — Caddy resolves module names
  at `/load` time and fails the config if the module is not linked.
- **Build args per provider** adds complexity (Dockerfile conditionals
  via `ARG`, CI matrix) with no real win; operators don't build their
  own caddy image, they pull the argos-edge one.
- **Multi-arch concerns**: all listed modules build cleanly on
  amd64 + arm64 (libdns is portable Go). No CGO dependencies.

**Only concern**: new versions of caddy-dns modules occasionally
bump their required Caddy version (saw it with hetzner v1 → v2).
The Dockerfile pins Caddy to `caddy:2-builder-alpine` which tracks
caddy 2.x latest. Pin a specific minor (e.g. `caddy:2.9-builder-alpine`)
to prevent a module-compat break from breaking the build mid-release.

---

## 6. UI design

### Settings → DNS Providers (new page)

Layout: cards grid, one per provider supported.

Each card:

- Provider name + logo placeholder.
- **Enabled** toggle (checkbox). Disabling + save clears no
  credentials — the row stays in DB, just `enabled=0`.
- Credentials form (visible when toggle is ON):
    - One input per credential field (from the static catalog).
    - Password fields use a `type="password"` input; unchanged-value
      sentinel `__UNCHANGED__` follows the existing OIDC pattern
      (`backend/internal/crypto/crypto.go:23`).
    - Required fields marked; optional fields labelled.
    - Helper text linking to the provider's docs for "how to get this
      token".
- **Test connection** button (optional, v1.3.1 candidate).
    - Calls a panel endpoint that uses the provider's SDK to do a
      cheap read (list zones). Returns pass/fail.
    - Not critical for v1.3.0 — the real test is "did Caddy issue a
      cert" which already produces a clear error in
      `caddy_error.log`.

### Host form

Existing radio group: `DNS` / `HTTP` / `TLS-ALPN` (at
`docs/features/reverse-proxy.md` "TLS challenges" table).

Extension: when `DNS` is selected, a second dropdown appears below:

```
DNS provider:  [ Cloudflare         ▼ ]
               Only providers enabled in Settings → DNS providers are listed.
               Configure one first if the dropdown is empty.
```

Auto-selection:

- If only one provider is enabled → auto-select it, hide the dropdown,
  show a small caption "Using <provider> from Settings".
- If multiple enabled → dropdown with the enabled providers, default
  to the currently saved value, or cloudflare for new hosts.
- If none enabled → show an amber warning with a deep link to
  Settings → DNS providers. Block save.

### Validation rules

- `tls_challenge = 'dns'` requires `tls_dns_provider` to point at an
  **enabled** row in `dns_providers`. Enforced at API level (same
  handler that today validates `tls_challenge=dns` against the
  existence of `CLOUDFLARE_API_TOKEN` — see `api/hosts.go:417`).
- Hosts with a disabled provider keep the value in DB (so re-enabling
  the provider restores them) but the reconciler emits a clear error
  and skips issuance for that host.

---

## 7. Migration + backward compatibility

### Migration 024

- Create `dns_providers` table with seed rows for each supported
  provider (all `enabled=0` by default).
- Idempotent re-seed on upgrade: `INSERT OR IGNORE` so later
  migrations adding new providers do not blow away operator
  config for existing rows.

### Migration 025

- Add `hosts.tls_dns_provider` column with default `'cloudflare'`.
- No CHECK; value is catalogue-validated at API.

### Boot-time migration

- On panel startup, if `CLOUDFLARE_API_TOKEN` env is set AND the
  cloudflare row is `enabled=0` (no credentials), auto-enable the
  row and encrypt the env value into `credentials_encrypted`.
- Log a one-time INFO line advising the operator to remove the env
  from `.env` at their next convenience. Keep the env var as a
  fallback reader for one more release (v1.3.x), then deprecate.

### Env var override (consistency with ACME CA precedence)

Mirror the existing `ARGOS_ACME_CA_URL` pattern
(`backend/internal/caddycfg/acmeurl.go`, see `api/settings.go:31`):

- `ARGOS_DNS_PROVIDER_OVERRIDE=<name>` forces every DNS-01 host onto
  the named provider regardless of DB. Emergency escape hatch.
- `ARGOS_DNS_PROVIDER_OVERRIDE_CREDS=<json>` supplies credentials if
  the DB has none for that provider. JSON blob format matching the
  provider's credential shape.

Nice-to-have; not required for v1.3.0 ship. Defer unless there's a
clear operator need.

### Rollback path

v1.3 → v1.2 rollback requires:

1. Set every `hosts.tls_dns_provider='cloudflare'` (or whatever was
   in use).
2. Re-populate `CLOUDFLARE_API_TOKEN` in `.env`.
3. Run `down024_dns_providers` migration (drops the table + column).

Document this in `docs/operations/upgrading.md`.

---

## 8. Complexity estimate

| Component | Effort | Notes |
|---|---|---|
| Migrations 024/025 | S | Standard CREATE TABLE + ALTER TABLE. |
| Catalogue + provider metadata Go package | S | Static struct: name, fields, libdns import path. ~200 LOC. |
| Credentials CRUD API | M | PUT /api/dns-providers/:name, encrypt on save, decrypt on reconcile. Mirror OIDC pattern. |
| caddycfg generator branching | M | Per-provider JSON shape; one switch in `buildChallenges`. Simple if we fix the shape as `map[string]string` plus a "coerce region-to-us-east-1" kind of defaults layer. |
| xcaddy Dockerfile update | S | 10 lines, pin-caddy-builder. |
| Boot-time CF env import | S | One function in main.go, idempotent. |
| UI Settings page (React) | M | New page, form per provider, encrypted-field pattern. Reuse OIDC form components where possible. |
| UI host form dropdown | S | Add dropdown, load enabled providers on mount, validation. |
| Notifications hook | XS | Nothing new; renewal-fail already emits `cert_renewal_failed`. |
| Docs | M | One new page + updates to reverse-proxy.md, add provider-specific setup guides (1 page each or a single "per-provider" page). |
| Tests | M | caddycfg tests per provider (JSON shape snapshots), boot-time migration, API CRUD, UI e2e on at least one provider. |

**Total: MEDIUM.** Estimate 2-3 focused weeks for Tier 1 (5 providers)
with Options 2 + bundle-everything decisions. Tier 2 (3-4 more
providers) adds 3-5 days of mostly provider-metadata + testing
(architecture is done once).

---

## 9. Sub-phasing

### Sub-phase A — core architecture + 2 providers (1 week)

- Migrations 024/025.
- Catalogue package with cloudflare + route53.
- Credentials encryption + API.
- caddycfg generator switch.
- Dockerfile: add route53.
- CF env-import boot migration.
- Basic tests.
- Ships as `v1.3.0-alpha` internally.

This is the **risky part**. If inline-decrypted creds turn out to
leak somewhere we didn't foresee, we catch it here with two
providers, not ten.

### Sub-phase B — UI + 3 more providers (1 week)

- Settings DNS providers page.
- Host form dropdown.
- Add digitalocean, hetzner, porkbun to catalogue + Dockerfile.
- Per-provider docs page.
- End-to-end tests.
- Ships as `v1.3.0-beta`.

### Sub-phase C — Tier 2 expansion (3-5 days)

- gandi, desec, ovh, duckdns, acmedns to catalogue + Dockerfile.
- Per-provider docs.
- Ships as `v1.3.0` GA.

Sub-phase C is parallelizable — adding a provider is catalogue
entry + docs page + Dockerfile `--with` line + regenerate caddy
image. Zero architecture changes.

---

## 10. Risks and open questions

### Risks

1. **Image size**. Adding 10 DNS providers grows the caddy image by
   ~30MB compressed, dominated by AWS SDK for route53. If this
   matters, ship only Tier 1 (5 providers, ~20MB growth) and defer
   Tier 2 to a later release.
2. **Library churn**. caddy-dns modules occasionally bump their
   required Caddy version. Mitigation: pin a Caddy minor version in
   the Dockerfile, test the full build in CI before release.
3. **Credential exposure via admin API**. Option 2 (inline creds)
   makes `GET /config/` return plaintext secrets. Acceptable given
   the admin API is not exposed on the host, but must be documented.
4. **Namecheap license**. The repo has no LICENSE file. **Exclude
   from v1.3** until upstream clarifies; adding it would create a
   redistribution risk for the argos-edge image we publish.
5. **Migration race on upgrade**. If a user upgrades with
   `CLOUDFLARE_API_TOKEN` set and the panel's auto-import runs, then
   they downgrade without running the down migration, they now have
   the token in both `.env` and the DB. Harmless but confusing.
   Mitigate with clear "downgrade deletes DB-stored creds" doc.
6. **Provider API rate limits during reconcile burst**. If 50 hosts
   all use route53 and the panel reconciles because of a config
   change, Caddy fires 50 order starts simultaneously. AWS will throttle.
   Same issue exists today with Cloudflare but is less acute because
   CF has generous limits. Not a new problem, but worth noting;
   Caddy's certmagic has built-in retry + jitter.

### Open questions

1. **Do we want `Test connection` in v1.3.0 or defer?** Pro: catches
   typos at save time. Con: adds one API dep per provider (panel
   needs to call each DNS API, which is the whole point of having
   Caddy do it). I'd defer. The first cert-issuance attempt already
   produces a clear error.
2. **Provider-by-provider docs page or one mega-page?** Given we have
   ~10 providers, a single "DNS providers" page with anchored
   subsections is probably less overhead than 10 pages. Each section:
   "how to get a token for $PROVIDER", "required fields", "scopes".
3. **Is `tls_dns_provider` stored per host, or inherited from a
   global default?** Currently proposed per-host. Alternative: a
   global `settings` entry `dns.default_provider` with per-host
   override. More settings to manage, fewer host-form fields. Pick
   per-host for now (matches current `tls_challenge` column
   placement); revisit if operators complain.
4. **What about rfc2136?** Niche but covers self-hosted DNS. The auth
   material is a TSIG key file (file content, not string), which
   breaks the "paste credentials into a form field" UX. Out of scope
   for v1.3; if an operator asks, document a manual Dockerfile
   override + compose env path.
5. **Libdns fork caveat.** caddy-dns modules depend on libdns
   providers, which are community-maintained. A handful have fewer
   eyes than the underlying provider SDK; review each module's
   dependencies before including. (Already screened the Tier 1 picks
   against last-commit activity.)

---

## 11. Alternatives to bundling caddy-dns modules

### Alternative A — Document acme.sh + Import (already shipped in v1.2)

Any provider we don't ship natively can use the v1.2.0 workflow:
install acme.sh on any machine, run `acme.sh --dns` with the
provider-specific plugin (acme.sh has 150+), import the resulting
cert via Certificates → Imported.

**Pro**: zero new code, ships immediately.

**Cons**: manual renewal every ~60 days (v1.2 docs explicitly
covers this); operator must run acme.sh somewhere; switches context
from the panel to a CLI.

### Alternative B — HTTP-01 covers everything with an open :80

HTTP-01 (`tls_challenge='http'`) is already shipped, requires zero
DNS credentials, works for anyone with port 80 open to the internet.
This covers a large fraction of homelab setups where the only
blocker for ACME is "I don't use Cloudflare".

**Pro**: already there, no setup.

**Con**: doesn't cover CGNAT, tunnel-only setups, or wildcard certs.

### Alternative C — TLS-ALPN-01 on :443

Same as HTTP-01 but for operators whose :80 is blocked. Already
shipped.

### What do DNS providers actually add?

Native DNS providers are strictly necessary for:

- **Wildcard certs** (only DNS-01 supports them).
- **CGNAT / Cloudflare Tunnel / ngrok** setups where no public port
  is reachable.
- **Internal-only hosts** that should not be exposed to the internet
  for validation.

For all other cases, HTTP-01 / TLS-ALPN-01 / acme.sh + Import cover
the need.

---

## 12. Recommendation

### Primary recommendation: ship Tier 1 only in v1.3, not all 10 providers

**v1.3.0 scope: Cloudflare (already) + route53 + digitalocean + hetzner
+ porkbun.**

Reasons:

1. **The marginal user per provider drops quickly after the top 5.**
   Route53 is AWS ubiquity, DigitalOcean is homelab default, Hetzner
   is EU homelab default, Porkbun is the popular indie registrar.
   That's the 80% of real demand.
2. **Image size and build time are linear in provider count.** 5
   providers is ~20MB image growth; 10 is ~30MB. For self-hosted this
   is fine either way, but there's no reason to pay the full cost
   without user demand.
3. **Per-provider support cost is real.** Every module we ship we
   promise to maintain (bump when upstream bumps, test on each Caddy
   release, debug credential issues users hit). Shipping 5 costs
   ~40% of shipping 10.
4. **The architecture is the expensive part, not the providers.**
   Sub-phase A + B deliver the architecture and the UI. Sub-phase C
   (Tier 2) is a trivial expansion that can happen lazily — one PR
   per provider when a user asks.

### Secondary recommendation: **scope the feature deliberately**

This feature has been asked for but may not be as big as it sounds:

- **Users with Cloudflare** already work — no change.
- **Users with port 80/443 open** already work (HTTP-01 /
  TLS-ALPN-01) — no change needed.
- **Users on acme.sh workflow** (v1.2 path) can keep using it as a
  fallback for unsupported providers.
- **The feature moves the needle only for users who have a DNS
  provider we ship AND are behind CGNAT AND want zero-touch
  renewals.**

That intersection is real (EU homelabers on Hetzner, AWS users,
CGNAT users with a DO account) but smaller than "users who asked
for more DNS providers" suggests.

### Green-light criteria

Proceed with v1.3 DNS providers expansion if:

- There is active operator demand for at least 2 specific providers
  (not just "more providers" in the abstract).
- The architecture decision (Option 2 — inline creds on /load) is
  acceptable given the trust-boundary implications (documented but
  unchanged from current caddy admin API exposure).
- Sub-phase A (1 week) can land in a single focused sprint.

### Defer criteria

Defer to v1.4 or later if:

- Feedback says HTTP-01 or acme.sh + Import is covering the case.
- Time / capacity is better spent elsewhere (logs/alerts/backups
  features have more demand signal).

---

## 13. Appendix — concrete shape of the generator change

The current `buildChallenges` at `caddycfg.go:995-1011`:

```go
func buildChallenges(c models.TLSChallenge) challenges { ... }
```

…becomes something like:

```go
// Signature change: accepts a resolved provider-creds blob.
func buildChallenges(c models.TLSChallenge, prov *ResolvedDNSProvider) challenges {
    switch c {
    case models.TLSChallengeHTTP:
        return challenges{HTTP: &httpChallenge{}}
    case models.TLSChallengeTLSALPN:
        return challenges{TLSALPN: &tlsALPNChallenge{}}
    case models.TLSChallengeDNS:
        fallthrough
    default:
        return challenges{
            DNS: &dnsChallenge{
                Provider: buildDNSProvider(prov),
            },
        }
    }
}

// ResolvedDNSProvider carries the provider catalogue entry + the
// decrypted credentials blob. Populated by the reconciler before the
// caddycfg generator runs.
type ResolvedDNSProvider struct {
    Name        string            // "cloudflare", "route53", etc.
    Credentials map[string]string // decrypted field values
}

// dnsProvider struct switches from a fixed shape to a JSON-tagged
// arbitrary map (Caddy accepts extra keys on provider blocks).
type dnsProvider map[string]any

func buildDNSProvider(p *ResolvedDNSProvider) dnsProvider {
    m := dnsProvider{"name": p.Name}
    for k, v := range p.Credentials {
        m[k] = v
    }
    return m
}
```

The generator stays provider-agnostic. The **catalogue** (separate
package, `internal/dnsproviders/catalog.go`) owns the per-provider
shape: which fields are required, which are optional, how to convert
a DB-stored blob into the `Credentials` map. Adding a provider =
one entry in the catalog + one line in the Dockerfile.

The reconciler loads `dns_providers` rows at the start of each
reconcile, decrypts once, hydrates the ResolvedDNSProvider per host
based on `hosts.tls_dns_provider`. Zero per-host decrypt work for
two hosts using the same provider.

---

## TL;DR

- **Library catalogue**: ship Tier 1 (cloudflare + route53 +
  digitalocean + hetzner + porkbun) in v1.3.0. Add Tier 2 (gandi,
  desec, ovh, duckdns, acmedns) in v1.3.x lazily when requested.
  Skip namecheap (license unclear).
- **DB**: dedicated `dns_providers` table, JSON blob encrypted with
  the existing AES-GCM cipher, one row per supported provider with
  enable/disable toggle.
- **Host**: new `tls_dns_provider` column, default `cloudflare`,
  validated at API level against enabled providers.
- **Credentials → Caddy**: inline decrypted values into the /load
  JSON (Option 2). No env-var rewrite, no container restart on
  rotation. Caddy admin API trust boundary is unchanged.
- **xcaddy**: bundle everything at build time. Pin Caddy minor
  version. ~20MB image growth for Tier 1.
- **UI**: new Settings → DNS providers page with per-provider card;
  host form gains a dropdown that appears when challenge=DNS.
- **Migration**: boot-time auto-import of existing
  `CLOUDFLARE_API_TOKEN` env into DB, one-time log notice, env as
  fallback for one release.
- **Effort**: MEDIUM, ~2-3 weeks focused. Sub-phaseable (A=core+2
  providers, B=UI+3 providers, C=Tier 2).
- **Recommendation**: green-light if there is specific operator
  demand for at least 2 named providers. Otherwise defer — HTTP-01
  and acme.sh + Import already cover most of the "not Cloudflare"
  cases. The feature is real but not as urgent as the "more DNS
  providers" framing implies.
