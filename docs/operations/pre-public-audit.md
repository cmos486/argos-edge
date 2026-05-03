# Pre-public release audit (v1.3.36.8)

Read-only audit of the argos-edge repo before
`gh repo edit --visibility public`. This page is the
PHASE 0 deliverable; PHASE 1 fixes are deferred to a
separate decision.

**Audit date**: 2026-05-03
**Audit scope**: README, CLAUDE.md, docs/ portal, CHANGELOG,
sanitization sweep, public-readiness checklist
**Reference release**: v1.3.36.8 (latest tag), v1.3.35
(latest panel binary)

## Executive summary

| Category | Status | Blockers? |
|---|---|---|
| README narrative | ✓ Coherent | no |
| CHANGELOG format / coverage | ✓ Coherent (61 entries) | no |
| Docs portal cross-refs / image embeds | ✓ Clean | no |
| `check-no-personal-data.sh` (3 patterns) | ✓ PASS | no |
| **Source-code sanitization (extended sweep)** | ✗ FAIL | **yes (S)** |
| CLAUDE.md currency | ✗ Stale | yes (M) |
| `verification-report.md` currency | ✗ Stale | yes (M) |
| `SECURITY.md` (responsible disclosure) | ✗ Missing | yes (M) |
| GitHub `.github/` templates | ✗ Missing | no (cosmetic) |
| LICENSE | ✓ Present (BSL 1.1) | no |
| `CONTRIBUTING.md` | ✓ Present at `docs/` (GitHub-recognized) | no |

**Recommendation at audit time**: NOT yet safe to flip
public. Four gating items bundled into v1.3.37 doc/
hygiene release.

**Status post-v1.3.37**: all four gating items
**RESOLVED** — see [Resolution](#resolution) below for
the per-item fix mapping.

## Resolution

v1.3.37 (2026-05-03, doc + sanitization release; tooling-only,
panel binary unchanged at v1.3.35) addressed every gating
item above:

| Audit ID | Fix shipped in v1.3.37 |
|---|---|
| C1 — `TODO(kilian)` markers | 5× source markers rewritten to `TODO(maintainer)`; CHANGELOG line 3954 rephrased to drop the literal quote; `check-no-personal-data.sh` Pattern D (`\bkilian\b` case-insensitive, LICENSE excluded) added as regression-guard |
| S1 — CLAUDE.md staleness | `Estado actual` bumped to v1.3.36.8 + panel-binary clarification; eight-strike → eleven-strike; smoke count 13 → 18 (with the 5 post-v1.3.32 additions enumerated); migration count clarified (30 files up to migration 033, schema-frozen since v1.3.33); pattern-bracket extended to v1.3.30-v1.3.36 |
| S2 — `verification-report.md` staleness | Header bumped to v1.3.36.8 gate; 5 new smoke rows added (country-reconciler, lapi-flush-cap, deploy-rebuild, demo-environment, capture-automation); summary table reflects 18 total / 16 PASS / 1 deferred / 1 legacy-skip; recommendation paragraph references the eleven-strike pattern + this audit doc |
| P1 — `SECURITY.md` missing | New 1-page policy at repo root: GitHub Security Advisories as primary reporting channel + no-detail-GitHub-issue fallback; supported-versions matrix; 7/14/30/release-window response targets; 90-day default coordinated disclosure; in-scope / out-of-scope partition (panel binary YES, upstream Caddy/CrowdSec/Coraza NO); empty hall-of-fame stub |

Items 6-9 (operator decision: defer post-public). Item 5
(LICENSE Licensor name) is intentional + legally-required;
Pattern D explicitly excludes LICENSE so the regression-guard
won't flag it.

## Critical findings

### C1 [HIGH] — `TODO(kilian)` markers leak operator's real first name

**Severity**: high (operator PII in source).
**Effort**: S (~10 min mechanical replace + script update).

`check-no-personal-data.sh` covers three patterns
(`cmos486.es`, operator LAN `192.168.{3,5}.x`, gmail
handle `discodurovirtualk`) but **does not catch the
operator's real first name** when it appears in
`TODO(kilian)` markers. Sweep results:

| File | Line | Marker |
|---|---|---|
| `backend/internal/totp/challenge.go` | 126 | `TODO(kilian): dead? no caller exists; ...` |
| `backend/internal/appsec/status.go` | 72 | `TODO(kilian): dead? no caller exists; ...` |
| `backend/internal/appsec/status.go` | 94 | `TODO(kilian): dead? no caller exists; ...` |
| `backend/internal/backup/scheduler.go` | (1 hit) | `TODO(kilian): ...` |
| `frontend/src/pages/Backup.tsx` | 666 | `TODO(kilian): no /api/backup/next_runs ...` |
| `CHANGELOG.md` | 3954 | "...marked 5 ambiguous ones with `TODO(kilian): dead?`" |

**Recommended fix**: replace `TODO(kilian)` with `TODO`
or `TODO(maintainer)` across the 5 source files; leave
the CHANGELOG line alone (it documents a past sweep that
itself used the marker — historical context, not a leak
to future readers if the markers themselves are removed
from active code; alternatively rephrase to "marked 5
ambiguous ones with TODO comments").

**Also**: extend `check-no-personal-data.sh` with
Pattern D = `\bkilian\b` (case-insensitive,
word-boundary) to enforce the regression-guard. This
matches the eight-strike pattern: catch the foot-gun
once, codify in the gate, can't sneak back.

### C2 [INFO, not a leak] — LICENSE Licensor name

`LICENSE` lines 12 + 14 contain "Kilian Ubeda" as the
named licensor and copyright holder:

```
Licensor:             Kilian Ubeda (cmos486)
Licensed Work:        argos-edge 1.0.0
                      The Licensed Work is (c) 2026 Kilian Ubeda.
```

**Verdict**: **NOT a leak.** A BSL 1.1 license
**requires** a named licensor for legal validity, and
the copyright notice on a published work follows the
same convention. This is intentional. No action needed,
but flagging for awareness when reviewing the
`TODO(kilian)` regression-guard pattern (Pattern D
must not flag `LICENSE`; add an explicit exception).

## Stale documentation findings

### S1 [MEDIUM] — CLAUDE.md is 3 minor versions behind reality

| Line | Current text | Reality |
|---|---|---|
| 12 | `Estado actual: v1.3.33 estable` | v1.3.36.8 |
| 90 | `Histórico de 8 incidentes a través de v1.3.18-v1.3.33` | 11 strikes per memory (latest v1.3.34.3) |
| 108 | `Patterns memorizados (v1.3.30-v1.3.33)` | should be (v1.3.30-v1.3.36) |
| 150 | `CAPI shape lesson (v1.3.33)` | last touch v1.3.33 — accurate as historical marker |
| 194 | `Estado actual: 33 migraciones (v1.3.33 latest)` | bump migration count if any added since v1.3.33 |
| 240 (smoke list intro) | `13 smoke scripts cubren el verification matrix` | **18** smoke scripts present in `scripts/smoke/` |

**Effort**: M (~20 min). Read CLAUDE.md once, refresh
five version markers, recount smoke scripts (18 = 13
original + 4 v1.3.32 + capture-automation.sh +
country-reconciler.sh + deploy-rebuild.sh +
demo-environment.sh — verify the categorization).

### S2 [MEDIUM] — `verification-report.md` cites old version + smoke count

`docs/operations/verification-report.md`:

| Line | Current text | Reality |
|---|---|---|
| 3 | `This page is the v1.3.32 verification gate` | should be v1.3.36.8 |
| 13 | `Existing smoke scripts: 9` | 9 → 14 (or recount per current taxonomy) |
| 14 | `New smoke scripts (v1.3.32): 4` | redo bucket boundaries |
| 15 | `**Total smoke scripts**: 13` | **18** |
| 16 | `EFFECT-verified PASS against prod stack v1.3.31` | should be v1.3.35 (latest panel binary) |

**This page is the single-source verification gate**
for public release per its own opening line. It must be
refreshed before flipping public, not after.

**Effort**: M (~30-45 min). Re-tabulate per-feature
smoke matrix; verify each smoke script still covers
the documented EFFECT. Some smokes added v1.3.32-v1.3.36
(country-reconciler.sh v1.3.33, capture-automation.sh
v1.3.36.x, demo-environment.sh v1.3.35,
deploy-rebuild.sh v1.3.34.3, lapi-flush-cap.sh v1.3.33,
scenario-descriptions.sh v1.3.30) need rows.

### S3 [LOW] — `docs/screenshots/README.md` carries 9× `TODO embed in features/X.md`

Inventory tracking notes flagging features pages that
have eligible screenshots but no `![]()` embed yet:

```
features/crowdsec.md           — 4 screenshots awaiting embed
features/security-overview.md  — 3 screenshots awaiting embed
features/drift-detection.md    — 1 screenshot awaiting embed
features/country-bans.md       — 1 screenshot awaiting embed
```

**Verdict**: not a public-release blocker (pages render
fine without embeds; text content covers the feature).
Operator workflow in progress. Can be addressed
incrementally post-public.

**Effort**: S per page (5 min each = ~45 min total) but
**not gating**.

## Public-readiness gaps

### P1 [MEDIUM] — `SECURITY.md` missing (responsible disclosure policy)

argos-edge is a security tool (WAF + reverse proxy +
SSO). Visitors expect a vulnerability-reporting policy.
GitHub looks for `SECURITY.md` at:

- root
- `.github/`
- `docs/`

**None present.** When GitHub finds it, the repo gets a
"Security" tab with a "Report a vulnerability" button
backed by the policy text.

**Effort**: M (~30 min). Recommended content:

- Supported versions (latest minor + N-1)
- Reporting channel (GitHub Security Advisories or
  email)
- Expected response SLA
- Disclosure timeline policy (90-day default? coordinated?)
- Out-of-scope (homelab self-hosted scope, not cloud
  service)
- Hall of fame / acknowledgements section (optional)

For a solo-maintained homelab project, a 1-page
SECURITY.md is appropriate; cribbing the GitHub
Security Advisory pattern is fine. Place at root or
`.github/`.

### P2 [LOW] — `.github/ISSUE_TEMPLATE/` missing

Optional but helpful for filtering bug-vs-feature
reports + reducing back-and-forth on "what version /
what panel mode / what stack". Recommended templates:

- `bug_report.md`: version, panel mode, stack components,
  reproduction
- `feature_request.md`: use case, alternatives considered

**Effort**: S (~15 min). Not a blocker for public flip.

### P3 [LOW] — `.github/PULL_REQUEST_TEMPLATE.md` missing

Optional. If solo-maintained accepts no PRs in
practice, can skip; if PRs are welcome, a 1-page
template (description, smoke results, sanitization
verification) sets expectations.

**Effort**: S (~10 min). Not a blocker.

### P4 [INFO] — `CONTRIBUTING.md` placement

GitHub recognizes `CONTRIBUTING.md` at root, `.github/`,
or `docs/`. argos-edge has it at
`docs/CONTRIBUTING.md`, which IS recognized. Symlink or
move to root only if you want the link to render in
the GitHub PR-create flow with shorter path. Not
gating.

## What's already clean

- **README.md** — narrative is coherent (title → tagline
  → hero → why → features → quickstart → access modes →
  arch → verifying → docs → license). Hero shot embedded
  as of commit `8b5475e` (today). Quickstart commands
  current. License + BSL 1.1 conversion date documented.
- **CHANGELOG.md** — Keep a Changelog format throughout;
  61 entries from v1.0.0 to v1.3.36.8; latest entry
  matches today's tag.
- **docs/CONTRIBUTING.md** — well-written, sanitization-
  focused, codifies placeholder conventions (RFC 2606 +
  RFC 5737).
- **mkdocs.yml** — nav coherent; 110 published pages;
  release-notes section complete; `exclude_docs` correctly
  scopes out internals/, planning/, screenshots/README.md,
  CONTRIBUTING.md.
- **`.github/workflows/`** — three workflows (docs.yml,
  personal-data-guardrail.yml, release.yml). No inline
  secrets; standard `${{ secrets.* }}` references.
- **Docs portal cross-refs** — Explore agent verified
  zero broken internal links across 268 markdown links.
- **Image embeds** — all 14 referenced screenshots exist
  in `docs/screenshots/`.
- **Per-feature doc currency** — feature pages
  (drift-detection, country-bans, appsec, crowdsec,
  reverse-proxy, etc.) reflect v1.3.36.x feature set.
  Provenance markers ("v1.3.27 added", "v1.3.31 async")
  are correct historical context, not staleness.
- **CAPTURE-automation flow** — operator workflow for
  sanitized screenshots is documented in
  `docs/screenshots/README.md` and codified in
  `scripts/capture/`.

## Recommendation: priority order

| # | Fix | Severity | Effort | Gating? |
|---|---|---|---|---|
| 1 | C1: replace `TODO(kilian)` × 5 + Pattern D in script | HIGH | S | **yes** |
| 2 | S2: refresh `verification-report.md` (v1.3.36.8 + 18 smokes) | MEDIUM | M | **yes** |
| 3 | S1: refresh CLAUDE.md (5 version markers + smoke count) | MEDIUM | M | **yes** |
| 4 | P1: add `SECURITY.md` (responsible disclosure) | MEDIUM | M | **yes (security project)** |
| 5 | C2 review: ensure Pattern D excludes LICENSE | INFO | S (with #1) | n/a |
| 6 | P2: `.github/ISSUE_TEMPLATE/` | LOW | S | no |
| 7 | P3: `.github/PULL_REQUEST_TEMPLATE.md` | LOW | S | no |
| 8 | S3: backfill 9× screenshot embeds in features/ pages | LOW | S each | no |

**Bundled release recommendation**: ship items 1-4 as
**v1.3.37** (doc + sanitization release; tooling-only,
`argosVersion` stays `1.3.35.4`). Estimated total
effort: 2-3 hours. Items 5-8 can ship as v1.3.37.x or
folded into next feature release.

After v1.3.37 ships, the repo is publication-ready.

## What was checked

| File / surface | Method | Result |
|---|---|---|
| `README.md` | full read | ✓ |
| `CLAUDE.md` | full read | ✗ stale |
| `CHANGELOG.md` | header + version inventory | ✓ |
| `LICENSE` | head | ✓ (intentional name) |
| `mkdocs.yml` | nav + exclude_docs | ✓ |
| `docs/architecture/` (4 files) | Explore agent | ✓ |
| `docs/features/` (~17 files) | Explore agent | ✓ |
| `docs/operations/` (~14 files) | Explore + manual on verification-report | ✗ stale |
| `docs/workflows/` (6 files) | Explore agent | ✓ |
| `docs/getting-started/` (3 files) | Explore agent | ✓ |
| `docs/reference/` (4 files) | Explore agent | ✓ |
| `docs/release-notes/` (61 versions) | inventory + spot-check | ✓ |
| `docs/screenshots/` (24 PNGs + README) | inventory + visual on hero candidates | ✓ + 9 TODO embeds (S3) |
| `docs/CONTRIBUTING.md` | head | ✓ |
| `.github/workflows/` (3 files) | grep secrets/tokens | ✓ |
| `.github/ISSUE_TEMPLATE/`, `PULL_REQUEST_TEMPLATE.md` | exists check | ✗ missing (P2, P3) |
| Sanitization: `cmos486.es`, op LAN, gmail | `check-no-personal-data.sh` | ✓ |
| Sanitization: WAN IP `79.116.27.251` | manual grep | ✓ clean |
| Sanitization: bot tokens, API keys | regex grep | ✓ clean |
| Sanitization: real names (kilian/ubeda/basetis) | manual grep | ✗ FAIL (C1) |
| Sanitization: personal email domains | regex grep | ✓ clean |

## Notes for the future

- **Pattern D** addition to `check-no-personal-data.sh`
  closes the gap that let `TODO(kilian)` markers
  survive 36+ releases. Adding new patterns to the gate
  is the v1.3.15 contract — patterns codify lessons.

- **Verification-report cadence**: the page is meant to
  be re-run on "any future release that might regress a
  covered surface" per its own opening, but in practice
  it has frozen at v1.3.32. A lightweight cron-style
  pre-tag checklist ("did the smoke matrix grow / a
  smoke change behavior?") would prevent the next
  N-version drift.

- **CLAUDE.md update cadence**: this is operational
  onboarding for future Claude sessions; staleness
  there compounds the "Eight-strike pattern" problem
  (now eleven). Refresh per-quarter or per-major-feature
  set, not per-release.
