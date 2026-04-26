# Documentation audit (post-v1.3.33, pre-public)

> **Status**: Read-only audit produced 2026-04-26. Maps every
> documentation surface against the v1.3.20-v1.3.33 feature
> reality. Output drives the v1.3.34 doc-refresh release scope.

## TL;DR

| | |
|---|---|
| Total docs/*.md files | 97 |
| Release notes coverage | 100% (every tagged release has a file) |
| CHANGELOG entries v1.3.20+ | Complete + format-consistent |
| Screenshots | 23 (22 real + 1 placeholder) |
| Last touch on `docs/features/` | 2026-04-25 (v1.3.19 era) |
| Last touch on `docs/architecture/` | 2026-04-20 (pre-v1.3.20) |
| **Surfaces critically stale for public release** | **3 (README, CLAUDE.md, reference/api.md)** |
| **Stale-but-not-blocker** | 6 (architecture, 4 features, 1 screenshot set) |

The good news: the release-process discipline shipped clean.
Every tag has a release-notes file; the CHANGELOG covers every
release. The bad news: the user-facing surfaces (README, the
docs portal's overview + features + reference, the screenshots)
all lag the past 13 releases by 1-2 weeks of intense feature
work. Pre-public refresh is non-trivial.

## Section 1 — Inventory

### 1.1 README.md

- **Path**: `/README.md`
- **Last edit**: 2026-04-20 (commit `137d424` — BSL license + GitHub repo metadata)
- **Size**: 11587 bytes
- **Status line**: `"v1.0.0 — first stable release"` (badge link works; status text 12+ releases stale)
- **Phase-language**: still present (`Phase 4`, `Phase 6` — pre-stable terminology)
- **v1.3.X mentions**: zero
- **Quickstart functionality**: looks correct (`docker compose up -d`); not re-verified since v1.0
- **Verdict**: **STALE-CRITICAL** for public release

### 1.2 docs/ tree (97 files)

```
docs/
├── index.md                          (overview, hero shot)
├── overview.md                        (mode matrix)
├── phase1-dns.md                      (legacy; not in nav)
├── CONTRIBUTING.md
├── architecture/  (4 pages)           (last touch 2026-04-20)
├── features/      (14 pages)          (last touch 2026-04-25 = v1.3.19)
├── getting-started/ (3 pages)         (last touch 2026-04-21)
├── internals/     (2 pages)           (deep-dives, not nav)
├── operations/    (11 pages)          (last touch 2026-04-26 = v1.3.32)
├── planning/      (3 pages)           (deferred features; not in nav)
├── reference/     (4 pages)           (last touch 2026-04-21)
├── release-notes/ (40+ files)         (100% tag coverage)
├── screenshots/   (23 PNGs + README)
├── tls/           (1 page)
└── workflows/     (7 pages)           (last touch 2026-04-21)
```

### 1.3 CHANGELOG.md

- **Format**: Keep a Changelog v1.1.0; valid 34 entries
- **v1.3.20-v1.3.33 entries**: ALL present
- **Special markings preserved**: `v1.3.20 - INCOMPLETE FIX` (audit
  trail of the failed first attempt at country-block) — good
- **Verdict**: **OK**

### 1.4 docs/release-notes/

100% coverage of every git tag. Verified files for: v1.0.0,
v1.0.1, v1.1.0, v1.1.1, v1.2.0, v1.3.0 through v1.3.33,
v1.3.27.1, plus prereleases under `prereleases/`. **Verdict: OK**.

### 1.5 Screenshots

23 files in `docs/screenshots/` (the duplicates in
`site/screenshots/` are mkdocs build artifacts):

| Filename | Likely UI surface | Real / placeholder |
|---|---|---|
| login.png | /login | real (~few KB) |
| dashboard-overview.png | / dashboard | real |
| dashboard-security.png | dashboard security widget | real |
| security-overview.png | /security/hosts (per-host) | real |
| host-form.png + host-form-dns-provider-dropdown.png | host edit modal | real |
| hosts-list-auth-column.png | /hosts | real |
| target-group-form.png + target-group-first-target.png + target-group-two-targets.png | target group flow | real |
| settings-panel.png + settings-dns-providers.png | /settings | real |
| sso-allowlist.png | OIDC allowlist | real |
| backup-settings.png + backups-list.png | backup UI | real |
| logs-browser.png | /logs | real |
| threats-decisions.png | older /threats tab | real |
| appsec-status.png + appsec-metrics.png | older /appsec | real |
| geoip-status.png | /settings geoip | real |
| notifications-deliveries.png | /notifications | real |
| totp-setup.png | TOTP onboarding | real |
| placeholder.png | (1x1 transparent fallback) | 68B placeholder |

22/23 are real, 1 is the documented placeholder. **Verdict for
freshness**: every one captures a UI surface from
**pre-v1.3.20**. None of the post-v1.3.20 features (drift
indicators, Scenarios tab tooltip, AppSec tuning tab,
true_detect_mode checkbox, async country expansion progress bar,
reconciler state column, scenario descriptions ⓘ glyph) is
photographed.

### 1.6 CLAUDE.md

- **Path**: `/CLAUDE.md`
- **Last edit**: 2026-04-18 (commit `44f5c3c` — initial scaffolding, phase 0 architecture)
- **Phase-language**: `"Si estamos en Fase 0..."` — pre-stable
- **References**: `"Lee ARCHITECTURE.md antes de cualquier cambio estructural"` — but `/ARCHITECTURE.md` does not exist at root anymore
- **v1.3 features mentioned**: zero
- **Eight-strike pattern**: not surfaced
- **Reverse-sentinel pattern**: not surfaced
- **Async-job pattern**: not surfaced
- **Verdict**: **STALE-CRITICAL** for future Claude sessions
  (memory system in `~/.claude/projects/.../memory/MEMORY.md`
  IS up-to-date, but CLAUDE.md is the human-facing project
  brief that any new Claude session reads first)

### 1.7 Architecture diagrams

4 pages in `docs/architecture/`, all last edited 2026-04-20:
- `components.md` (3 containers, 1 docker network) — **PRE-DATES** the panel sub-services that shipped after: drift detector goroutine, country JobRunner, country Reconciler. The "what runs inside the panel container" picture is incomplete.
- `request-flow.md` — should still be roughly correct (request hits
  Caddy → bouncer → AppSec → upstream); doesn't reflect the
  reverse-sentinel data flow nor the panel-side reconciler ticks.
- `storage.md` — covers the SQLite tables; **MISSING**
  `country_expansion_jobs` (v1.3.31), `country_ban_expansions.state`
  column (v1.3.33), `appsec.scenarios.drift_state` /
  `appsec.tuning.drift_state` settings rows (v1.3.27).
- `threat-model.md` — should be roughly correct;
  the eight-strike-pattern lessons learned about LAPI shape
  collisions could fit here as "operational caveats".

All four contain `mermaid` blocks; the diagrams need re-render
for the v1.3.20-v1.3.33 additions.

## Section 2 — Gap analysis (feature → doc coverage)

| Feature (release) | Status | Notes |
|---|---|---|
| Country expansion sync (v1.3.21) | **DOCUMENTED-STALE** | Pre-v1.3.22 supernet rollup; pre-v1.3.31 async; pre-v1.3.33 reconciler |
| Country expansion async (v1.3.31) | **UNDOCUMENTED** | No feature page; 202+poll flow not in user-facing docs |
| Drift detection (v1.3.27) | **UNDOCUMENTED** | No feature page; the `/security/drift` endpoint, the 60s ticker, the badges in tabs — none of it documented |
| LAPI WAL fix (v1.3.28) | **DOCUMENTED-STALE-OPS** | Mentioned in release notes; not surfaced as a config knob in `features/crowdsec.md` or `operations/tuning.md` |
| Per-host true_detect_mode (v1.3.29) | **UNDOCUMENTED** | DETECT badge in hosts list, the Edit Host checkbox, the profiles.yaml splice mechanism — all undocumented |
| Scenario descriptions (v1.3.30) | **UNDOCUMENTED** | The ⓘ tooltip + the reverse-sentinel pattern that powers it |
| Reverse-sentinel pattern (v1.3.30) | **UNDOCUMENTED** | Internal architecture pattern; should land in `architecture/components.md` or a new `internals/sentinel-patterns.md` |
| Async-job pattern (v1.3.31) | **UNDOCUMENTED** | Same as above; the country-expansion-jobs table + worker is the first instance |
| Verification audit (v1.3.32) | **DOCUMENTED** | `operations/verification-report.md` is current |
| Alert-shape restructure + reconciler (v1.3.33) | **PARTIALLY-DOCUMENTED** | Internal to the panel; release notes cover the user-visible side. The `state` column on country_ban_expansions + the 5-min reconciler tick should land in `features/crowdsec.md` or a new `architecture/reconcilers.md` |
| Eight-strike upstream-behaviour pattern | **MEMORY-ONLY** | Lives in `~/.claude/.../memory/`; not in CLAUDE.md or the docs portal |
| AppSec tuning UI (v1.3.25) | **UNDOCUMENTED** | The threshold sliders, the sentinel writer, drift detection of tuning state |
| Scenarios management UI (v1.3.25) | **UNDOCUMENTED** | The PATCH-disable flow, the cscli scenarios remove path, the per-tab UI |
| sync-prod tooling (v1.3.26) | **DOCUMENTED** | `operations/deployment.md` is current |
| GitHub Actions auto-publish (v1.3.27.1) | **DOCUMENTED** | `operations/release-process.md` is current |
| AppSec block mode end-to-end | **DOCUMENTED** | `features/appsec.md` + `features/waf.md` are current at the v1.3.19 level (pre-v1.3.25 tuning UI) |
| Reverse proxy emission | **DOCUMENTED** | `features/reverse-proxy.md` |
| Authentication (local + OIDC + TOTP) | **DOCUMENTED** | `features/auth-local.md` + `features/auth-oidc.md` |
| Whitelist UI | **DOCUMENTED-STALE** | Mentioned in `features/security-overview.md`; the v1.3.19 sentinel-write flow not detailed |
| Banned IPs UI | **PARTIALLY-DOCUMENTED** | Mentioned but the UI pivot from /threats to /security/banned in v1.3.24 not reflected |
| Activity / audit log | **DOCUMENTED-STALE** | Pre-v1.3.24 tab structure |
| Dashboard widgets | **DOCUMENTED** | `features/observability.md`; the security widget refresh (v1.3.20-era) is OK |
| Recovery CLI subcommands | **DOCUMENTED** | `reference/cli.md` |

### Smoke scripts as documentation

13 smoke scripts in `scripts/smoke/` — each carries an extensive
header comment documenting what it tests, the EFFECT it
verifies, the env vars, exit codes, and reproduction
instructions. **Verdict: well-documented at the script level.**
Cross-reference from a `docs/operations/smoke-suite.md` would
help discovery, but the in-script docs are sufficient for the
operator who finds them.

### docs/reference/api.md (the single biggest gap)

| Endpoint family | Documented? |
|---|---|
| `/api/auth/*` | yes |
| `/api/hosts/*` | yes |
| `/api/security/decisions/*` (v1.3.23) | partial — needs verification |
| `/api/security/whitelist/*` (v1.3.23) | partial |
| `/api/security/scenarios*` (v1.3.25) | **NO** (0 mentions) |
| `/api/security/appsec-tuning*` (v1.3.25) | **NO** |
| `/api/security/drift` (v1.3.27) | **NO** |
| `/api/security/countries/{cc}/expand` (v1.3.31) | **NO** (old body-shape entry may be stale) |
| `/api/security/jobs/{id}` + `/api/security/jobs?country=X` (v1.3.31) | **NO** |
| Scenario descriptions enrichment in `GET /api/security/scenarios` (v1.3.30) | **NO** |

Result: `docs/reference/api.md` is **roughly v1.3.20-era** and
needs a full sweep to add v1.3.21-v1.3.33 endpoints + remove
the (likely-stale) sync-shape `POST /api/security/countries/expand`
entry that v1.3.31 replaced.

## Section 3 — Screenshot inventory (UI surface → has-screenshot)

| UI surface | Has screenshot? | Notes |
|---|---|---|
| Login page | ✅ current | login.png |
| Dashboard | ✅ current | dashboard-overview.png + dashboard-security.png |
| Hosts list | ✅ current | hosts-list-auth-column.png — pre-v1.3.29 (no DETECT badge) |
| Host edit modal | ✅ current | host-form.png — **pre-v1.3.29** (no true_detect_mode checkbox) |
| Target groups | ✅ current | target-group-{form,first-target,two-targets}.png |
| /security/hosts (per-host security) | ✅ current | security-overview.png |
| /security/banned (Banned IPs tab) | ❌ MISSING | v1.3.24 introduced this tab; threats-decisions.png is the older /threats |
| /security/whitelist | ❌ MISSING | v1.3.24 tab |
| /security/activity | ❌ MISSING | v1.3.24 tab |
| /security/scenarios (with description tooltips) | ❌ MISSING | v1.3.25 tab + v1.3.30 ⓘ enrichment |
| /security/appsec (threshold tuning) | ❌ MISSING | v1.3.25 tab |
| Drift indicators (banner + tab dots) | ❌ MISSING | v1.3.27 surface |
| Country bans + async progress bar | ❌ MISSING | v1.3.31 surface |
| Country bans state=drifted indicator | ❌ MISSING | v1.3.33 (UI rendering deferred per release notes) |
| SelfBlockBanner v2 | ❌ MISSING | v1.3.23 surface |
| Settings page | ✅ partial | settings-panel.png, settings-dns-providers.png — pre-CountryBansSection async polling |
| AppSec status | ✅ stale | appsec-status.png — pre-v1.3.25 (no threshold sliders) |
| Logs browser | ✅ current | logs-browser.png |
| OIDC allowlist | ✅ current | sso-allowlist.png |
| Backups | ✅ current | backups-list.png + backup-settings.png |
| Notifications | ✅ current | notifications-deliveries.png |
| TOTP setup | ✅ current | totp-setup.png |
| GeoIP status | ✅ current | geoip-status.png |
| Threats tab | ✅ stale | threats-decisions.png — UI moved to /security/* in v1.3.24 |

**Net new captures needed for v1.3.34**: ~10 (the missing rows
above). **Net re-takes for stale-shape**: ~3 (host-form,
appsec-status, threats-decisions).

## Section 4 — Priority recommendations

### CRITICAL (blocker for public release)

1. **README.md rewrite** [M, ~1-2h]
   - Status line: drop "v1.0.0 first stable release"; replace with
     a feature-list paragraph that mentions drift detection,
     async country expansion, true_detect_mode, scenario
     descriptions, async-job pattern.
   - Drop phase-language; the project shipped v1.3.33 weeks ago.
   - Add a short feature matrix or bullet list pointing at the
     docs portal sections.
   - Verify quickstart still works with current `.env.example`.

2. **CLAUDE.md refresh** [S, ~30min]
   - Drop "Fase 0" language; project is at v1.3.33.
   - Drop the "Lee ARCHITECTURE.md" line (file doesn't exist).
   - Surface the eight-strike pattern + reverse-sentinel +
     async-job patterns at one-line-each density. Cross-link to
     the project memory in `~/.claude/.../memory/MEMORY.md` for
     the full writeups.

3. **docs/reference/api.md sweep** [L, ~2-3h]
   - Add v1.3.25-v1.3.33 endpoints (scenarios, appsec-tuning,
     drift, countries/{cc}/expand, jobs).
   - Remove or correct the v1.3.20-era body-based country expand
     entry (replaced by path-based in v1.3.31).
   - Verify every documented response shape against the current
     handler. The note at the top says "Authoritative source:
     backend/internal/server/server.go" -- that's still the
     contract, but docs/reference/api.md should not lag the code.

### HIGH (quick post-public win, days/weeks)

4. **docs/architecture/components.md update** [M, ~1h]
   - Add the panel-side sub-services (drift detector goroutine,
     country JobRunner + worker mutex, country Reconciler 5-min
     ticker).
   - Mermaid diagram refresh.

5. **docs/architecture/storage.md update** [S, ~30min]
   - Add `country_expansion_jobs` (v1.3.31).
   - Add `country_ban_expansions.state` column (v1.3.33).
   - Add settings keys for drift state (v1.3.27).

6. **New `docs/features/drift-detection.md`** [M, ~1h]
   - 60s reconciler ticker.
   - GET /api/security/drift response shape.
   - DriftBanner + per-tab dots UI.
   - Operator action when drift detected.

7. **New `docs/features/country-bans.md`** [M, ~1h]
   - Path-based POST endpoint.
   - 202 + job-polling flow.
   - Reconciler state field.
   - Operator workflow + the v1.3.31-era flush-cap caveat
     (now resolved by v1.3.33).

8. **Re-take ~10 missing screenshots** [M, manual; ~1-2h elapsed]
   - Banned IPs / Whitelist / Activity / Scenarios / AppSec
     tabs in /security.
   - Drift indicators (induce drift via cscli mutation).
   - Country bans async progress bar (mid-expansion shot).
   - Host edit modal with true_detect_mode checkbox.
   - DETECT badge on the hosts list.

9. **Update `docs/features/crowdsec.md` for new scope** [S, ~30min]
   - Note the LAPI WAL config (v1.3.28).
   - Mention the country reconciler.
   - Cross-link the alert-shape lesson (v1.3.33).

### LOW (eventual polish)

10. **`docs/operations/smoke-suite.md`** [S, ~30min]
    - Cross-reference all 13 smoke scripts in one page so
      operators discover them without scanning the directory.
    - Each entry: smoke name, what it asserts, when to run it.

11. **`docs/internals/patterns.md`** [M, ~1h]
    - Reverse-sentinel pattern (v1.3.30).
    - Async-job pattern (v1.3.31).
    - Eight-strike upstream-behaviour memo (excerpted from
      `~/.claude/.../memory/`).

12. **Re-take `host-form.png` + `threats-decisions.png` + `appsec-status.png`** [S, manual]
    - Stale-shape captures of UI that meaningfully changed.

## Suggested v1.3.34 doc-refresh release scope

**Option A — single bundled release (recommended)**:
- Items 1, 2, 3 (the three CRITICAL items) — ~4-6h
- Items 4, 5, 6, 7 (HIGH architecture + 2 new feature pages) — ~3-4h
- Item 8 (screenshots — ~10 captures) — ~1-2h elapsed (operator-mediated)
- Item 9 (crowdsec.md polish) — ~30min

Total estimated effort: **~10-12h focused work** + ~2h
operator-mediated screenshot capture. Single ship `v1.3.34`,
tagged as a "documentation refresh" release with no panel
binary change (precedent: `v1.3.27.1`).

**Option B — split (if preferred for incremental rollout)**:
- `v1.3.34`: items 1, 2, 3 (CRITICAL only) — ~4-6h. Public release
  unblocked.
- `v1.3.35`: items 4, 5, 6, 7, 8, 9 (HIGH + screenshots) —
  ~5-7h + 2h. Post-public polish.

**Recommendation**: Option A. The three CRITICAL items and the
HIGH items overlap substantially — once you're in the API
reference rewriting, you're 60% of the way through the
features/ pages they reference. Bundling preserves momentum +
keeps the public-release narrative consistent ("the docs match
v1.3.33" rather than "the docs match v1.3.33 except for these
gaps").

## What this audit does NOT cover

- Internationalisation (the docs are English-only; no
  translation coverage)
- SEO / portal styling
- Per-page word-count for readability
- Mobile responsiveness of the mkdocs-material theme
- Frontend in-app help text / tooltips
- API client SDKs (none exist; argos doesn't ship one)

## Recommendation: ready for public after v1.3.34?

The three CRITICAL items are blockers. Once they ship, the
public-facing surface is consistent: README points at a docs
portal whose API reference matches the binary, and CLAUDE.md
guides future Claude sessions accurately. The HIGH items are
post-public quality-of-life; the LOW items are polish.

**Proposed sequence**:

1. Ship `v1.3.34` doc-refresh (items 1-9 bundled per Option A).
2. Tag, the v1.3.27.1 release workflow auto-publishes.
3. Operator does the 10-screenshot capture pass; commit as a
   single "docs(screenshots): post-v1.3.34 captures" commit.
4. Repo flips to public via `gh repo edit --visibility public`.
5. LOW items become open issues on the public repo.
