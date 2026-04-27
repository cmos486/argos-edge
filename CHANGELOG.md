# Changelog

All notable changes to argos-edge are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.34.1] - 2026-04-27

Telegram notifications fix. Default `parse_mode` flips from
`MarkdownV2` to `HTML` so event types containing underscores
(`config_change`, `threat_ip_banned`, `cert_renewal_failed`,
etc.) stop tripping the Telegram parser. The MarkdownV2 escape
set has 18 reserved chars; HTML has 3 (`<`, `>`, `&`). Closes
the ninth strike in the upstream-behaviour pattern.

`argosVersion` and `frontend/package.json` deliberately stay at
`1.3.33` (same coherent-binary-line policy as v1.3.34); the
panel binary DOES require a rebuild this time to pick up the
new Go code in `templates.go` and `senders/telegram.go`.

### Added

- **`escapeHTML` template function** (`backend/internal/
  notifications/templates.go`). Wraps `html.EscapeString` from
  the Go stdlib; accepts `any` so callers can pipe string-typed
  aliases like `EventType` through it without printf coercion.
- **Unit tests** for the new HTML default template, escapeHTML
  on dynamic fields, the MarkdownV2 regression path, and the
  Telegram sender's parse_mode form-body shape (mock Bot API
  server).
- **`docs/features/notifications.md` parse_mode subsection**
  documenting HTML vs MarkdownV2 trade-offs, the no-forced-
  migration policy for existing pinned-MarkdownV2 channels, and
  a link to the Telegram Bot API HTML Style spec.

### Changed

- **Default Telegram template** (`templates.go::DefaultTemplate`).
  Now produces HTML (`<b>{{ .Type | escapeHTML }}</b>` +
  `<code>{{ .HostDomain | escapeHTML }}</code>` +
  `{{ .Message | escapeHTML }}`) instead of MarkdownV2.
- **Telegram sender empty-parse_mode fallback**
  (`senders/telegram.go`). Flipped from `MarkdownV2` to `HTML`
  for new channels with no pinned `parse_mode`.
- **`escapeMD` signature** widened from `func(string) string`
  to `func(any) string` so it accepts EventType aliases. Pure
  refactor: `fmt.Sprintf("%v", s)` on a string returns it
  unchanged.

### Fixed

- **Telegram deliveries failing silently on `config_change`,
  `threat_ip_banned`, and other underscore-bearing event types
  since v1.3.21.** The default template emitted
  `*{{ .Type }}*` without piping `.Type` through `escapeMD`,
  which made Telegram return 400 with a byte-offset
  "Character '_' is reserved" error. The HTML default
  sidesteps the entire MarkdownV2 reserved-char minefield.

## [1.3.34] - 2026-04-26

Documentation refresh release. **Zero panel binary change**;
`argosVersion` and `frontend/package.json` deliberately stay at
1.3.33. The four-component-or-tooling-only-no-version-bump
precedent (v1.3.27.1, v1.3.32) is reused here: the panel binary
at v1.3.34 is byte-identical to v1.3.33.

Closes the documentation-audit findings from `v1.3.32`'s
`docs/operations/documentation-audit.md`. Items 1, 2, 3, 4, 5,
6, 7, 9 from the audit are bundled; item 8 (10 missing
screenshots) is deferred to an operator-mediated capture session
post-tag and a follow-up commit.

### Added

- **`docs/features/drift-detection.md`** (NEW). Full v1.3.27
  drift-detector documentation: 60s reconciler ticker, the
  `/api/security/drift` response shape, the `appsec.scenarios.
  drift_state` + `appsec.tuning.drift_state` settings rows, the
  DriftBanner + per-tab dot UI behaviour, what to do when drift
  is detected, what this replaces (the v1.3.25 mark-applied
  buttons), limitations.
- **`docs/features/country-bans.md`** (NEW). Unified
  v1.3.21+v1.3.31+v1.3.33 country-bans story: why argos doesn't
  use scope=Country directly (upstream strike #2), the v1.3.33
  CAPI alert shape (1 alert with N decisions inside), the
  v1.3.31 async submit+poll model with the JobRunner
  single-worker mutex + boot-time recovery, the v1.3.33
  reconciler health check, operator workflow + tuning knobs +
  limitations. Cross-links to the smokes that verify each layer.

### Changed

- **`README.md`** rewritten. Drops the stale "v1.0.0 first
  stable release" status line + the phase-language framing
  (Phase 4 / Phase 6 / "currently on Phase 0"). Replaces the
  inline OIDC setup walkthrough with a feature-list +
  docs-portal pointer. Adds screenshot-placeholder TODO
  comments for the operator's post-tag capture session.
- **`CLAUDE.md`** rewritten as v1.3.33-aware Claude Code
  onboarding. Drops nonexistent-`ARCHITECTURE.md` reference;
  surfaces the eight-strike upstream-behaviour pattern + the
  reverse-sentinel pattern (v1.3.30) + the async-job pattern
  (v1.3.31) at one-line-each density with cross-links to the
  full project memory entries. Adds the working-agreement +
  smoke-suite + dual-dir deploy gap discipline as inline rules.
- **`docs/architecture/storage.md`** updated:
  `country_expansion_jobs` table (v1.3.31), the
  `country_ban_expansions.state` column (v1.3.33), the
  `appsec.*.drift_state` settings rows (v1.3.27), v1.3.18+
  hosts columns (lan_only, true_detect_mode, tls_acme_ca_url,
  tls_challenge, tls_dns_provider). New "Out-of-band sentinels"
  section covers both the v1.3.19+ panel→script direction and
  the v1.3.30 reverse-sentinel direction with the
  argos-scenarios-index.json example.
- **`docs/architecture/components.md`** updated. Internal-
  subsystems mermaid diagram now includes the drift detector,
  country JobRunner, country reconciler, public-IP detector.
  Goroutines table adds rows for each. New
  "Reconcilers verify what" subsection summarises the three
  drift surfaces. New "Smoke verification" subsection
  cross-references the per-feature smokes.
- **`docs/features/crowdsec.md`** polished. Updated panel role
  (was "Threats tab"; now "/security/* tabs + reconciler
  goroutines"). New "Scenarios management" subsection covers
  the v1.3.25 disable+sentinel+reload flow + drift detection.
  New "LAPI tuning" subsection covers the v1.3.28 WAL knob and
  the v1.3.31→v1.3.33 alert-shape lesson.
- **`docs/reference/api.md`** swept for v1.3.20-v1.3.33
  endpoints. Old `/api/threats/*` table removed. New
  `/api/security/*` table covers banned IPs / whitelist /
  activity / scenarios management / appsec tuning / drift /
  country bans (path-based) / job polling. Hosts section adds
  the v1.3.18+ fields documentation (lan_only,
  true_detect_mode, tls_acme_ca_url, tls_challenge,
  tls_dns_provider). Mark-applied retired endpoints documented
  as removed.
- **`mkdocs.yml`** nav. New `features/country-bans.md` and
  `features/drift-detection.md` entries; new
  `operations/documentation-audit.md` entry.

### NOT changed

- `argosVersion` / `frontend/package.json` deliberately stay at
  1.3.33. No panel rebuild required for this release; pull +
  redeploy mkdocs.
- All v1.3.33 backend / frontend / migration code unchanged.
- Smoke scripts unchanged (the v1.3.34 release introduces no new
  feature surface; the existing 13 smokes already cover what
  the new doc pages describe).

### Known gap (deferred to a post-tag follow-up)

Audit item #8: 10 missing screenshots (Banned IPs / Whitelist /
Activity / Scenarios / AppSec tabs in /security; drift
indicators; country bans async progress; host modal with
true_detect_mode checkbox; DETECT badge on hosts list; settings
DriftBanner). Operator runs a dedicated capture session
post-tag and commits as `docs(screenshots): post-v1.3.34
captures`. The new doc pages already render correctly without
the captures (mkdocs strict build clean); screenshots are
purely operator-visual polish.

### Smoke gate (mkdocs strict + sanitize)

- `mkdocs build --strict` — clean (3 unrelated planning notes
  remain intentionally outside nav, as before)
- `scripts/check-no-personal-data.sh` — clean (one operator-
  domain leak in CLAUDE.md caught + replaced)
- All cross-references in new pages resolve to existing anchors
  (the `#reconcilers-verify-what` anchor in components.md was
  added to support cross-linking from the two new feature
  pages)

## [1.3.33] - 2026-04-26

Critical fix release: closes the silent country-decision desync
discovered during v1.3.31 dogfood. The pre-v1.3.33 LAPI alert
shape (one alert per CIDR) collided with CrowdSec's
`flush.max_items: 5000` default cap, silently flushing older
`argos-country-*` alerts every time a new country expansion
pushed the alert count above 5000. The panel's
`country_ban_expansions` table claimed N countries banned;
LAPI had zero of them active.

Three bundled fixes:

### Fix 1: AddRangeDecisions shape restructure (root cause)

`backend/internal/crowdsec/client.go::AddRangeDecisions` now
emits ONE alert per call with all N decisions inside the
`decisions[]` array (CAPI / community-blocklist pattern), not
N alerts each carrying 1 decision. v1.3.22's per-chunk
failure isolation is preserved via 500-decision chunking, so
a 5009-CIDR country becomes 11 chunk-alerts instead of 5009
per-CIDR alerts.

Empirical proof (post-deploy prod stack):

```
country  ranges  v1.3.22 alerts  v1.3.33 alerts
-------  ------  --------------  --------------
NG          471             471               1
IR        1,454           1,454               3
BR        5,009           5,009              11
```

Mixed-origin batches now error explicitly (homogeneous-batch
contract); existing callers (Expander.Ban) already pass
homogeneous origin.

### Fix 2: country reconciler + migration 033

Migration 033 adds `state` column on `country_ban_expansions`
with CHECK constraint `('active', 'drifted')`. New
`country.Reconciler` runs every 5 minutes (configurable),
compares panel `cidr_count` vs LAPI count for each origin,
flips `state='drifted'` when divergence > 1%. Defensive layer
against any residual drift cause not covered by Fix 1
(manual cscli mutations, future shape changes, panel restart
during a writer window). 4 unit tests cover the classifier
tolerance, drift detection, recovery to active, and no-churn
when state already matches.

UI surfaces the state field in `GET /api/security/countries`
response. Frontend rendering of the drift indicator is queued
for a follow-up release; the API contract is in place.

### Fix 3: smoke isolation

`scripts/smoke/country-expansion-async.sh` defaults
`TEST_COUNTRY=XX` and `FAIL_TEST_COUNTRY=YY` (RFC 3166
reserved codes). The smoke refuses to run with placeholders
so cleanup cannot blanket-DELETE operator-created BR/TR
expansions. Operator must explicitly export real codes:

```bash
TEST_COUNTRY=BR FAIL_TEST_COUNTRY=TR ./scripts/smoke/country-expansion-async.sh
```

Same pattern as v1.3.21's `country-block.sh` from the
beginning -- v1.3.31's smoke shipped without this gate and
contributed to the dogfood incident.

### Added

- `scripts/smoke/lapi-flush-cap.sh`: 8-phase EFFECT smoke
  validating Fix 1. Asserts `delta == ceil(cidr_count/500)`
  per country expansion + no decision loss across multiple
  expansions.
- `scripts/smoke/country-reconciler.sh`: 5-phase smoke for
  Fix 2 (induce drift via cscli, wait for tick, assert
  state='drifted', re-emit, verify recovery to 'active').
  Operator-mediated due to the 5-min reconciler interval.
- `crowdsec.Client.CountDecisionsByOrigin(ctx, origin) -> int`:
  used by the reconciler.

### Memory updated

`project_four_strike_upstream_pattern.md` -> **eight-strike**
entry. Full root-cause writeup + the LAPI shape lesson:
"when emitting bulk LAPI data, mirror CAPI shape -- it's
the only shape upstream tested at scale".

### Smoke gate (all passes verified post-deploy)

- `lapi-flush-cap.sh`: NG 1 chunk + IR 3 chunks; +4 alerts
  total for 1925 CIDRs combined. No decision loss.
- `lapi-wal.sh`, `scenario-descriptions.sh`,
  `scenarios-toggle.sh`, `appsec-tuning.sh`,
  `host-crud.sh`, `whitelist-roundtrip.sh`: all PASS (no
  regression from the shape change).

### Operator validation required post-deploy

The operator's prod stack had 8 banned countries that
silently became 0 active LAPI decisions during v1.3.31.
After deploying v1.3.33, the operator re-applies the 8
expansions one at a time and verifies via
`cscli decisions list --origin argos-country-XX --limit 0 | wc -l`
that decisions persist across multiple expansions (no flush
cascade).

## [1.3.32] - 2026-04-26

Verification release. No new feature scope. v1.3.32 ran every
existing smoke against the live prod stack, identified
coverage gaps in the v1.3.20+ EFFECT-smoke regime, and shipped
4 new smoke scripts to close the highest-priority ones.
Establishes a single-source verification matrix in
`docs/operations/verification-report.md` that maps every
shipped feature to its smoke (or documents why no smoke
exists) so future releases can re-run the matrix before
tagging.

### Added

- **`scripts/smoke/auth-flow.sh`**: 4-phase login -> /me ->
  logout -> 401 lifecycle. Operator runs with their
  credentials (`ARGOS_USERNAME` + `ARGOS_PASSWORD`); detects
  TOTP-pending response and exits PASS-PARTIAL.
- **`scripts/smoke/host-crud.sh`**: 7-phase Host CRUD round-
  trip + Caddy admin reachability. Creates a placeholder
  test host bound to an existing target group, exercises
  POST -> GET -> toggle -> PUT -> DELETE -> 404 -> Caddy
  status.
- **`scripts/smoke/whitelist-roundtrip.sh`**: 8-phase
  panel -> sentinel -> argos-whitelist.yaml round-trip.
  POST whitelist -> GET shows -> sentinel populated ->
  setup-appsec.sh -> parser yaml has the IP -> DELETE -> all
  three surfaces clean again.
- **`scripts/smoke/banned-ips-roundtrip.sh`**: 5-phase
  cscli -> panel /security/decisions -> panel DELETE ->
  cscli round-trip. Accounts for the 15s `Client.ListDecisions`
  cache TTL (waits 17s between mutations and the next read).
- **`docs/operations/verification-report.md`**: the
  single-source verification matrix. Every shipped feature
  mapped to its smoke (12 PASS) or a documented coverage gap
  with rationale. Produces the "ready for public" verdict
  for v1.3.32.

### Verified (re-run against prod stack v1.3.31)

| Smoke | Result |
|---|---|
| `sync-prod.sh` | PASS (5/5) |
| `lapi-wal.sh` | PASS (3/3) |
| `scenario-descriptions.sh` | PASS (5/5) |
| `scenarios-toggle.sh` | PASS (8/8) |
| `appsec-tuning.sh` | PASS (6/6) |
| `drift-detection.sh` | PASS (12/12) |
| `true-detect-mode.sh` | PASS (8/8) |
| `country-expansion-async.sh` | PASS (4/4 happy; failure path skipped to avoid LAPI downtime) |
| `country-block.sh` | SKIP (legacy regression test for upstream-broken path; `country-expansion-async.sh` is the current contract) |
| `host-crud.sh` (new) | PASS (7/7) |
| `whitelist-roundtrip.sh` (new) | PASS (8/8) |
| `banned-ips-roundtrip.sh` (new) | PASS (5/5) |
| `auth-flow.sh` (new) | DEFERRED (operator-credential gated; cannot run unattended) |

### Coverage gaps documented (NOT shipping new smokes for these)

- Recovery CLI subcommands: operator-only, manually
  exercised during incident recovery. Each subcommand has
  `--help`.
- Self-block detection / banner v2: requires the operator's
  actual public IP to be banned to surface; cannot synthesise
  without breaking connectivity. Underlying API endpoint
  exercised indirectly.
- Activity / audit log: read-only query; broken queries
  render an empty tab with no incident risk.
- Dashboard widget: aggregated counters; verified implicitly
  via the underlying-data smokes.
- TOTP / 2FA enrollment, OIDC SSO, backup/restore,
  reverse-proxy healthcheck propagation, notifications:
  documented per `verification-report.md` as either external-
  dependency or operator-mediated.

### Mid-impl gotchas (caught + fixed pre-tag)

- **`/api/security/whitelist` returns `{entries: [...]}`,
  not a bare array.** Smoke initially `jq '.[]'`'d the
  envelope object. Fixed jq path.
- **`Client.ListDecisions` 15s cache TTL.** Smoke initially
  waited 1s after `cscli decisions add` and saw an empty
  panel response. Bumped to 17s. Documented in the smoke's
  comments + the verification report.
- **DELETE response shape**: `{deleted: 1, id: N}`, not
  `{deleted: true}`. Smoke jq assertion adjusted.

### Recommendation

**Zero blockers preventing public release.** Repo is
functionally verified end-to-end. Future releases re-run
the verification matrix from `docs/operations/verification-
report.md` before tagging.

## [1.3.31] - 2026-04-26

Async background-job for country expansion. The synchronous
v1.3.22 path (~30s blocking HTTP request for fragmented
countries like BR/IN; 20-min `WriteTimeout` ceiling) is
replaced by a submit + poll flow. Operators get an immediate
202, a live progress bar driven by chunk-by-chunk callbacks,
and graceful error reporting via the new
`country_expansion_jobs` table.

Establishes the **async-job pattern** for argos-edge: DB-backed
progress shadow + single-worker goroutine + boot-time
recovery. Reusable for future long-running operations (audit
retention sweeps, scenario re-installs, etc.) without further
infrastructure work.

### Added

- **Migration 032: `country_expansion_jobs`** with state enum
  `pending|running|completed|failed`, chunks_done/total/failed,
  cidr_committed, requested_count, error_message,
  created_at/started_at/completed_at, created_by.
- **`backend/internal/security/country/jobs.go`**: `JobRunner`
  with `Submit`, `Get`, `ListByCountry`, and `RecoverOnBoot`.
  Single-worker mutex (one expansion at a time globally;
  avoids the v1.3.22 LAPI WAL contention finding). Goroutine
  outlives the request via the panel's main-context.
  Boot-time recovery transitions any `pending|running` rows
  from a prior panel instance to `failed` with
  `error_message='panel restarted'`. 8 unit tests covering
  state lifecycle, progress callback, LAPI error path, mutex
  serialisation, recovery, list-by-country.
- **`Expander.BanWithProgress`**: refactored from the
  v1.3.22 chunk loop. Accepts a `ProgressFn` callback fired
  after each chunk's LAPI POST. The synchronous `Ban` is now a
  thin wrapper for callers that don't need progress.
- **`POST /api/security/countries/{cc}/expand`**: replaces
  the v1.3.21 body-based handler. Path-based shape; body is
  `{duration, reason}`. Returns `202 Accepted` + the new job
  row.
- **`GET /api/security/jobs/{id}`** + **`GET /api/security/jobs?country=XX&limit=N`**.
  Top-level `/security/jobs` (not nested under `/countries`)
  to leave room for future job types.
- **Frontend async polling** in `CountryBansSection`: POST
  -> 202 -> 1s polling loop -> progress bar (chunks_done /
  chunks_total + cidr_committed) -> success/error toast on
  terminal state. 10-minute polling cap; the row remains
  visible via the recent-jobs surface.
- **`scripts/smoke/country-expansion-async.sh`**: 8-phase
  EFFECT smoke. Happy path: submit -> poll -> assert
  state=completed -> assert decisions count > 4000.
  Failure path: stop crowdsec -> submit TR -> poll -> assert
  state=failed + error_message populated -> restart crowdsec
  + verify healthy.

### Changed

- Frontend `securityCountriesExpand` returns
  `CountryExpansionJob` (was `CountryExpansionResult`). Old
  `CountryExpansionResult` type is preserved for the
  synchronous Ban() callers in tests.
- The synchronous `POST /api/security/countries/expand`
  body-based endpoint is removed in favour of the path-based
  `{cc}/expand`. Programmatic clients of v1.3.30 need to
  update; the panel UI is the only known caller and is
  updated in the same release.

### Deferred (not in scope)

- **Cancel endpoint** -- the plan placeholder included
  `POST /api/security/countries/jobs/{id}/cancel`; cancellation
  requires threading a context-cancel through `Expander.Ban`
  that doesn't exist today. Skipped for v1.3.31.
- **WriteTimeout rollback** from 20m -> 30s. Reachable now
  that the expand endpoint returns 202 in <100ms; deferred to
  a follow-up.

### Smoke gate (8/8 PASS)

```
[1/8] POST /api/security/countries/BR/expand   202 + job_id=4
[2/8] poll until terminal                       <60s
[3/8] assert state=completed                    11/11 chunks; 5009 ranges committed
[4/8] cscli decisions list --origin ...         5009 decisions tagged argos-country-BR
[5/8] stop crowdsec                             OK
[6/8] POST .../TR/expand                        202 + job_id=5
[7/8] poll until terminal                       state=failed
                                                error_message='all 5 chunks failed: Post ... no such host'
[8/8] start crowdsec back; wait for healthy     OK (within 30s)
```

## [1.3.30] - 2026-04-26

Cosmetic enrichment: the Scenarios tab now surfaces each
scenario's hub-catalogue description as a hover tooltip.
Deferred from v1.3.25 because the catalogue file
`/etc/crowdsec/hub/.index.json` is mode 0600 root-owned and
cannot be read directly by the panel-as-nobody process via the
existing `/crowdsec-state` mount.

Establishes the **reverse-sentinel pattern**: prior sentinels
(`argos-true-detect-hosts.txt`, `argos-disabled-scenarios.txt`,
`argos-managed-profiles.yaml`, etc.) are written by the panel
and consumed by `setup-appsec.sh`. v1.3.30 inverts the
direction: `setup-appsec.sh` (running as root inside crowdsec)
writes `/shared/argos-scenarios-index.json` (mode 0644 by
default umask, panel-readable) and the panel consumes it.
Future panel-readable derivatives of crowdsec internal state
should follow the same pattern.

### Added

- **`crowdsec/setup-appsec.sh::emit_scenarios_index`**: parses
  `/etc/crowdsec/hub/.index.json` and emits a slimmed
  `{canonical_name: description}` JSON to
  `/shared/argos-scenarios-index.json`. Uses jq (apk-add
  on demand, ~1.2s, idempotent). Atomic-write + cmp-based
  no-op detection so runs without changes don't bump mtime.
- **`backend/internal/security/scenarios::DescriptionsLoader`**:
  panel-side reader with mtime-based cache invalidation. Each
  request stats the file; reload only when mtime advances.
  Nil-safe (Get on nil receiver returns ""). 7 unit tests
  cover the full lifecycle: missing file, valid lookup,
  mtime-driven reload, malformed-file resilience (in-memory
  map preserved on parse error), nil receiver, Reader
  enrichment integration, and empty-when-loader-nil.
- **`Scenario.Description`** field on the API response (json
  tag `description,omitempty`). Empty when the slimmed file
  hasn't been emitted yet (first boot post-upgrade) or when a
  scenario isn't in the hub catalogue.
- **`scripts/smoke/scenario-descriptions.sh`**: 5-step EFFECT
  smoke covering setup-appsec.sh emit, API coverage threshold
  (>= 90%), known-scenario substring assertion (CVE-2017-9841),
  graceful-degrade test (file absent -> API still returns
  scenarios), restore.

### Changed

- **Frontend Scenarios tab**: scenario name cell now carries
  a `title=` tooltip + a small `ⓘ` glyph when description is
  present. No badge / icon when description is empty (no
  visual noise for hub-misses).

### Smoke gate (5/5 PASS)

- 54/54 installed scenarios on the prod stack have
  description (100% on installed set; hub catalogue has 779
  total).
- `crowdsecurity/CVE-2017-9841` -> "Detect CVE-2017-9841 exploits"
  (matches the expected substring).
- Index file removed -> API returns scenarios with empty
  descriptions; no 500.
- Index file restored -> next request picks it back up via
  mtime invalidation.

## [1.3.29] - 2026-04-26

Activates the dormant `hosts.true_detect_mode` column (added
v1.3.19). Toggling the flag on a host now writes a CrowdSec
profiles.yaml entry that suppresses LAPI decision creation for
AppSec alerts whose `target_fqdn` / `target_host` matches the
host. Alerts continue to be logged; only the alert -> scenario
-> ban pipeline is intercepted. Useful for hosts whose
legitimate traffic triggers AppSec false positives (socket.io
polling, monitoring tools, hot-reload dev servers).

The original v1.3.27 plan rejected this path as
"upstream-unsupported"; v1.3.29 PHASE 0 spike + smoke proved
empirically that CrowdSec profile filter expressions can
access `Alert.Events[].Meta` via expr-lang's `any()` operator,
and that the suppression is real (smoke gate: synthetic LAPI
alert with remediation=true creates 1 decision when detect=off,
0 decisions when detect=on).

### Added

- **`backend/internal/security/files.go::WriteProfilesYAML`**:
  pure-string formatter + DB-backed writer. Generates the
  argos-managed YAML block from
  `SELECT domain FROM hosts WHERE true_detect_mode = 1 AND enabled = 1
  ORDER BY domain ASC`. Filter expression checks both
  `target_host` (outofband-scenario shape) and `target_fqdn`
  (inband WAF shape) for the host's domain. 5 unit tests cover
  zero-hosts placeholder, one-host filter shape, multi-host
  in-list join, deterministic re-runs, and quote escaping.
- **`crowdsec/setup-appsec.sh::splice_profiles_yaml`**: new
  function in `apply_panel_sentinels`. Splices the
  panel-emitted block between the existing
  `# >>>>> argos-managed: true_detect_mode hosts` markers in
  `/etc/crowdsec/profiles.yaml`. Idempotent (no-op when
  identical); when the file changes, sets
  `PROFILES_CHANGED=1` so main bounces the container via
  `kill -TERM 1` (CrowdSec does not hot-reload profile
  changes via SIGHUP; full restart required).
- **`scripts/smoke/true-detect-mode.sh`**: 8-step EFFECT smoke
  using LAPI direct-POST of a synthetic alert (target_fqdn
  meta + remediation=true). Bypasses the AppSec listener
  entirely so the test isolates the profile-filter logic
  rather than depending on the stack's listener config (the
  argos block-config inband listener does not feed
  `crowdsec-appsec-outofband` -- a real-attack-burst smoke
  would see 0 decisions in BOTH detect-on and detect-off
  phases, a false positive).
- **Frontend "True detect mode" checkbox** in the Edit Host
  modal Access section, plus a `DETECT` indicator badge on
  the hosts list.

### Changed

- **`backend/internal/reconciler/reconciler.go`**: replaced
  `WriteTrueDetectHosts` with `WriteProfilesYAML` in the
  reconcile chain. The v1.3.19 hostname-list-only sentinel
  (`argos-true-detect-hosts.txt`) is removed; the panel now
  emits the full YAML block directly.
- Frontend `Host` + `HostInput` types in `client.ts` now
  include `true_detect_mode`.

### Smoke gate (8/8 PASS)

Per the working agreement (smoke verifies effect, not specs):

1. PUT `true_detect_mode=true` on test host -> reconciler
   writes sentinel.
2. Sentinel `/shared/argos-managed-profiles.yaml` contains
   the test host.
3. `setup-appsec.sh` splices + restarts crowdsec.
4. Synthetic LAPI alert injection (target_fqdn=test_host,
   remediation=true).
5. `cscli alerts list` shows the alert.
6. **`cscli decisions list` shows 0 decisions** (the filter
   suppressed default_ip_remediation).
7. PUT `true_detect_mode=false` -> setup-appsec.sh re-splice
   -> inject same alert again.
8. **`cscli decisions list` shows 1 decision** (baseline
   default_ip_remediation fired without the filter).

### Mid-implementation lessons (added to seven-strike memo)

- **Meta key divergence**: inband WAF alerts use
  `target_fqdn`; outofband-scenario alerts use `target_host`.
  Filter checks both. PHASE 0 spike sampled only one alert
  shape (the outofband one); smoke caught the gap.
- **Bind-mount inode invalidation**: rsync replaces files via
  tempfile + rename (inode changes), but docker bind mounts
  resolve the path at container-start time and pin the
  inode. After `make sync-prod` of any bind-mounted script
  (setup-appsec.sh, Caddyfile, etc.), the operator must
  `docker compose restart <service>` for the new file to be
  visible inside the container.

### Deferred

None. v1.3.29 is the original v1.3.28 plan, fully delivered.

## [1.3.28] - 2026-04-26

CrowdSec LAPI latency fix: enables SQLite WAL mode on the
LAPI database so concurrent reads no longer block during
community-blocklist inserts. v1.3.26 dogfood logged 20+
slow `/v1/decisions` GETs (3-4s each) during the ~2-hourly
CAPI sync window; CrowdSec itself emits a startup warning
about the unresponsiveness. WAL mode lets readers proceed
concurrently with the writer at the cost of a `.db-wal`
sidecar file.

The per-host `true_detect_mode` work originally drafted as
v1.3.28 has been renumbered to v1.3.29 (planning doc moved to
`docs/planning/v1.3.29-true-detect-mode.md`); v1.3.28 was
claimed by this LAPI fix.

### Changed

- **`crowdsec/config.yaml.local`**: added `db_config.use_wal:
  true`. CrowdSec merges this with the upstream `config.yaml`
  default (`use_wal: false`), so the local override is enough.
  Applies on the next crowdsec container restart; SQLite issues
  `PRAGMA journal_mode=WAL` against the existing DB file (no
  data migration; no downtime beyond the ~3s restart).
- **`backend/cmd/argos/main.go`** + **`frontend/package.json`**:
  panel `argosVersion` + frontend version bumped to 1.3.28 even
  though only the crowdsec config changed. The panel binary
  string reflects the stack release; operators read it in the
  panel footer to know which release they are on.

### Added

- **`scripts/smoke/lapi-wal.sh`**: live-stack smoke that asserts
  three things end-to-end:
  1. `PRAGMA journal_mode` returns `wal`
  2. The CrowdSec startup warning ("sqlite is not using WAL
     mode...") is absent from the current container's logs
     (scoped via `.State.StartedAt` so a previous container's
     pre-fix logs don't false-positive)
  3. `.db-wal` sidecar exists when writes have happened
- **Investigation summary**: see the v1.3.28 release notes for
  the full PHASE 1-3 spike record (suspect ranking, diagnostic
  data, idle vs concurrent latency measurements).

### Smoke gate

- Pre-fix idle latency: `cscli alerts list` 300-932ms
- Post-fix idle latency: `cscli alerts list` 294-460ms
- Post-fix concurrent reads (during cscli alerts list bursts):
  217-314ms (no WAL-vs-non-WAL differential observable at idle;
  the real win is during the next CAPI sync, when readers no
  longer block on the writer)
- `scripts/smoke/lapi-wal.sh` PASS post-deploy

## [1.3.27.1] - 2026-04-26

Tooling-only patch on top of v1.3.27. Adds the
`.github/workflows/release.yml` workflow that auto-publishes a
GitHub release on every tag push, sourced from the matching
`docs/release-notes/<tag>.md`. Closes the manual-release-creation
loop where tags landed but the Releases page stayed stuck on an
older version.

Four-component version is a one-time precedent reserved for
tooling-only patches with no panel runtime change. The argos
binary at v1.3.27.1 is byte-identical to v1.3.27;
`backend/cmd/argos/main.go` `argosVersion` and
`frontend/package.json` `version` intentionally remain at
`1.3.27`.

### Added

- **`.github/workflows/release.yml`**: tag-push -> publish
  GitHub release flow. `softprops/action-gh-release@v2`,
  `permissions: contents: write` (same pattern as the existing
  `docs.yml` gh-pages deploy). Pre-release tags (containing a
  `-`) are flagged `prerelease=true` and read from
  `docs/release-notes/prereleases/<tag>.md`.
- **`docs/operations/release-process.md`**: pre-tag checklist,
  tag-push command shape, troubleshooting, manual-backfill via
  `gh release create` for tags that predate this workflow.

### Smoke gate

The workflow run itself IS the smoke. Tag push -> Actions UI
shows the run -> `/releases/tag/v1.3.27.1` lists the release
with the body of `docs/release-notes/v1.3.27.1.md`.

## [1.3.27] - 2026-04-26

Drift detection for the v1.3.25 scenarios + AppSec tuning UIs.
Replaces the operator-trust "Mark as applied" model with a real
comparison between panel intent (sentinel files + settings) and
CrowdSec runtime state, read every 60s from the read-only
/crowdsec-state mount.

The bundled per-host true_detect_mode work originally planned
for v1.3.27 was deferred to v1.3.28 after a pre-implementation
verification confirmed the upstream caddy-crowdsec-bouncer plugin
does not support per-handler appsec_url overrides (sixth case in
the upstream-behaviour pattern; planning doc:
docs/planning/v1.3.28-true-detect-mode.md).

### Added

- **`backend/internal/security/drift` package**: filesystem-based
  drift detector. Reads installed scenarios via the existing
  scenarios.Reader and parses argos-tuning.yaml SecAction lines
  for the inbound/outbound thresholds (regex match on
  `tx.inbound_anomaly_score_threshold=NN`). Periodic 60s loop
  mirrors publicip.Detector. 11 unit tests covering empty-set,
  drift-detected, drift-cleared, mount-missing, partial-file,
  panel-defaults paths.
- **`/api/security/drift` GET endpoint**: serves the cached
  snapshot persisted in settings rows
  `appsec.scenarios.drift_state` + `appsec.tuning.drift_state`.
  Response shape:
  ```json
  {
    "scenarios": { "drift_detected": bool, "expected_disabled": [...], "actually_enabled": [...] },
    "appsec_tuning": { "drift_detected": bool, "expected_inbound": int, "actual_inbound": int, ... },
    "last_check_at": "RFC3339"
  }
  ```
- **`scripts/smoke/drift-detection.sh`**: 12-step end-to-end
  smoke. PATCH disable scenario -> wait 65s -> drift=true -> run
  setup-appsec.sh -> wait 65s -> drift=false. Repeat for AppSec
  tuning threshold. Cleanup restores pre-test state.
- **Frontend drift indicators**: top-of-page DriftBanner above
  the tab strip + per-tab amber dots beside the Scenarios +
  AppSec labels. Polls `/api/security/drift` every 10s.

### Changed

- **PendingReloadBadge replaced**. Old behaviour: derived from
  `last_modified_at > last_applied_at` and required the operator
  to click "Mark as applied" after running setup-appsec.sh. New
  behaviour: drift detector observes the runtime sync and the
  banner clears itself within ~60s of the script completing.
- **Migration 031** drops the `appsec.scenarios.last_applied_at`
  + `appsec.tuning.last_applied_at` settings rows. The `.up` is a
  pair of idempotent DELETEs; the `.down` is a no-op (the keys
  would re-populate on first PATCH if the v1.3.26 panel were
  rolled back, but the mark-applied endpoints are removed in
  v1.3.27 so there is nothing to restore).
- **API removals**: `POST /api/security/scenarios/mark-applied` +
  `POST /api/security/appsec-tuning/mark-applied` deleted along
  with their handlers and the `last_applied_at` /
  `reload_needed` response fields.

### Deferred

- **Per-host true_detect_mode (FEATURE 2)**: cut from this
  release after pre-flight verified the upstream Caddy plugin
  cannot route appsec_url per-handler. The dormant
  `hosts.true_detect_mode` column (migration 028) remains. See
  `docs/planning/v1.3.28-true-detect-mode.md` for the v1.3.28
  spike plan: profiles.yaml whitelist re-evaluation vs upstream
  PR.

### Smoke gate

Per the working agreement (smoke verifies effect, not specs):
- `scripts/smoke/drift-detection.sh` PASSES against the live
  argos-prod stack: both surfaces flip drift_detected=true after
  PATCH + wait, then clear after setup-appsec.sh + wait.
- `make sync-prod-dry` clean (or expected-only diff) before any
  panel restart, per dual-dir deploy gap discipline.

## [1.3.26] - 2026-04-26

Operator tooling release. Closes the dual-dir deploy gap that
v1.3.25 prod-smoke caught (operational `crowdsec/setup-appsec.sh`
stuck at pre-v1.3.19 while panel image was at v1.3.25 because no
automated sync existed between `~/argos-edge/` and `~/argos-prod/`).

### Added

- **`scripts/sync-prod.sh`** -- rsync source-of-truth checkout to
  the operational dir. Diff-first preview, idempotent (no-op when
  in sync), refuses to run when paths are wrong / DST is not an
  argos checkout / SRC==DST / non-TTY without --yes / rsync
  missing. Explicit denylist for operator-managed files
  (docker-compose.override.yml, .env*), data dirs (data/,
  backups/), VCS state (.git/), build outputs (frontend/dist/,
  backend/static/assets/, node_modules/, site/), tarballs, and
  editor / OS noise.
- **`scripts/smoke/sync-prod.sh`** -- self-smoke for sync-prod.
  5 gates against tmpdirs (refuses invalid paths, no-op safe,
  drift propagates, operator files protected, excludes work).
  Safe to run on any host; never touches real operational dirs.
- **`Makefile`** -- top-level operator targets: `sync-prod`,
  `sync-prod-dry`, `deploy-prod` (sync `--yes` + docker compose
  build + up), `verify-prod` (post-deploy scenarios + appsec
  smokes), `smoke-self` (sync-prod self-smoke). `ARGOS_PROD_DIR`
  env var overrides the default `~/argos-prod`.
- **`docs/operations/deployment.md`** -- new ops page covering
  single-dir simple case + dual-dir homelab pattern. Documents
  sync semantics, denylist, refuse-to-run conditions, drift
  recovery via `diff -rq`, and the release-note checklist for
  changes that touch bind-mounted files.

### Not changed

- Zero backend code changes, zero frontend code changes, zero
  migration. Panel image / Caddyfile contents / crowdsec config
  unchanged from v1.3.25. This release is operator tooling only.

### Smoke gate

Per the working agreement (smoke verifies effect, not specs):
- Self-smoke: `make smoke-self` runs the 5 sync-prod gates
  green against ephemeral tmpdirs.
- Real preview: `make sync-prod-dry` against the operator's live
  `~/argos-edge` / `~/argos-prod` reports the expected v1.3.25-era
  drift as itemized rsync output.
- Real apply: `make sync-prod` propagates the diff; subsequent
  `make sync-prod-dry` reports no changes.
- Deploy idempotent: `make deploy-prod` against a freshly-synced
  operational dir runs sync (no-op) + docker compose build
  (cached) + up (no-op container state) without errors.

## [1.3.25] - 2026-04-26

The remaining two items from the v1.3.20+ elevated scope:
Scenarios management UI and AppSec threshold tuning UI. Both
follow the v1.3.19 sentinel-file pattern; co-developed.

### Added

- **`backend/internal/security/scenarios` package** -- reads
  installed-scenario state from a read-only filesystem mount
  (LAPI v1.7.7 has no hub API; verified via 5-min pre-impl
  check against the route table in
  pkg/apiserver/controllers/controller.go). 6 unit tests.
- **Two new sentinel files** under /data/shared/:
  - argos-disabled-scenarios.txt (one canonical name per
    line; setup-appsec.sh runs `cscli scenarios remove
    --force` per line)
  - argos-appsec-tuning.txt (key=value with inbound +
    outbound thresholds; script regenerates argos-tuning.yaml
    on next run)
- **Six new /api/security/* endpoints**:
  - GET / PATCH / mark-applied for scenarios (3)
  - GET / PATCH / mark-applied for appsec-tuning (3)
  All audit-logged. PATCH-with-state for idempotency.
- **/security tabs grew from 3 to 5**: Scenarios + AppSec
  joined Banned IPs / Whitelist / Activity. Both new tabs
  render a persistent "Pending reload" badge when
  last_modified > last_applied so the operator can see at
  a glance which sentinel needs a setup-appsec.sh run.

### Changed

- **docker-compose.yml**: added `crowdsec_config:/crowdsec-state:ro`
  read-only mount on the argos service. Panel enumerates
  scenarios from /crowdsec-state/scenarios/*.yaml (each a
  symlink whose target encodes the owner prefix).
- **crowdsec/setup-appsec.sh**:
  apply_panel_sentinels() now regenerates argos-tuning.yaml
  from the operator-set thresholds (overriding the
  copy_file'd default) AND removes panel-disabled scenarios
  via cscli. Order: install collections → copy files →
  regenerate tuning → run hardcoded v1.3.19 removes → apply
  panel disables → write whitelist → reload.

### Smoke gate

Per the working agreement (smoke verifies effect, not specs):
- Disable scenario via UI → reload script → cscli confirms
  removed → mark as applied → badge clears.
- Re-enable scenario via UI → reload script → cscli shows
  it reinstalled.
- Change inbound_threshold via UI → reload script →
  argos-tuning.yaml regenerated with new value.
- Empty crowdsec scenarios dir → UI explainer, no crash.

### Limitations documented

- Drift detection (panel queries cscli to verify actual state
  matches panel intent) is v1.3.26+. v1.3.25 trusts operator's
  "Mark as applied" assertion. Badge tooltip warns: "if the
  script errored, marking applied won't fix the underlying
  state".

### Not in v1.3.25

- Drift detection.
- Scenario descriptions from .index.json.
- Per-rule-ID disable (smaller granularity than per-scenario).

## [1.3.24] - 2026-04-26

Frontend half of the security-panel work the v1.3.23 backend
endpoints staged. Pure-frontend release; zero new backend
surface, zero migrations.

### Added

- **`/security` is now the global security panel** with three
  tabs over the v1.3.23 endpoints:
  - **Banned IPs**: search/filter/paginate over LAPI
    decisions, per-row Unban.
  - **Whitelist**: add scope=ip or scope=range entries, list
    + per-row Remove. Every action surfaces the
    setup-appsec.sh reload command in the toast.
  - **Activity**: paginated audit-log with expandable JSON
    diff per row.
- **Dashboard "Bans & whitelist" widget** between the
  existing Security (WAF activity) and Health sections.
  Polls /api/security/dashboard-stats on the standard 30s
  refresh: active bans + scope breakdown, whitelist entries,
  audit_last_24h, country-expansion rollup with top
  countries.
- **api-client methods + types** for the 7 v1.3.23 endpoints
  (securityListDecisions, securityDeleteDecisionByID,
  securityListWhitelist, securityDeleteWhitelistEntry,
  securityAuditLog, securityDashboardStats,
  securityPublicIPSelf).

### Changed

- **Per-host WAF overview moved from `/security` to
  `/security/hosts`.** The old URL is the natural home for
  global security state (bans/whitelist/audit); per-host
  config is its own concern. Mixing them forced operators to
  mentally filter "is this view per-host or global" every
  time.
- **Bookmark-rescue + discoverability**: `/security` shows a
  session-dismissable banner pointing operators with
  bookmarks at `/security/hosts`. The tab strip carries a
  visually-distinct `Hosts ↗` link (separator + arrow icon)
  for first-time visitors who want to find the moved page.

### Smoke gate

Per the working agreement (smoke verifies effect, not specs):

- Tab nav: each tab renders, data matches the corresponding
  /api endpoint.
- Banned IPs Unban: cscli ban -> table row -> Unban click ->
  cscli list returns empty for that IP.
- Whitelist add/remove: round-trip + reload-command toast.
- Activity tab: post-v1.3.23 entries show source_ip; legacy
  entries gracefully render empty.
- Hosts link routes to /security/hosts (host-WAF overview
  unchanged).
- Bookmark-rescue banner dismisses cleanly for the session.
- Dashboard widget renders with non-zero counts post-smoke.
- NO tag until smoke real PASSes against prod stack.

### Not in v1.3.24 (deferred to v1.3.25)

- Scenarios management UI (sentinel pattern + setup-appsec.sh
  extension).
- AppSec threshold tuning UI (same pattern).

Both follow the v1.3.19 sentinel-file architecture and share
script-extension work, so co-developing them is less work
than splitting.

## [1.3.23] - 2026-04-26

First half of the security-panel work from the v1.3.20+
elevated scope. Backend + SelfBlockBanner v2 ship here;
the full /security UI tabs land in v1.3.24.

### Added

- **`hosts` migration 030**: `sessions.client_ip` +
  `sessions.xff_chain` columns. Both NULL-allowed --
  pre-v1.3.23 sessions stay valid; banner v2 just doesn't
  see those IPs.
- **`session.CreateOpts`** to pass IP context at
  session-create time. Login (auth.go), OIDC, and TOTP
  paths all now persist the request's resolved client IP +
  X-Forwarded-For chain.
- **`session.ListActiveIPsForUser`** returns distinct
  non-NULL client_ip values for a user's active sessions.
  Banner v2 uses this to enumerate IPs.
- **`backend/internal/security/publicip` package** with the
  Detector (ipify-by-default background poller). 1h
  interval, configurable URL, env-var disable, settings-
  rehydrate at boot. 6 unit tests cover JSON / plaintext /
  malformed responses and disabled-mode.
- **Audit IP capture**: handlers.go::audit() now folds
  `_source_ip` + `_xff_chain` into log_entries.raw. v1.3.24
  Activity tab renders these.
- **`/api/security/check-self` multi-IP shape**: keeps the
  v1.3.19 fields for backwards compat; adds
  `current_session_ip`, `public_ip_self`,
  `active_session_ips`, `any_banned`, `banned_count`,
  `banned_ips` (per-IP rows with source labels).
- **Seven new `/api/security/*` endpoints**:
  - `GET /decisions` (filter/search/paginate)
  - `DELETE /decisions/{id}`
  - `GET /whitelist`, `DELETE /whitelist/{id}`
  - `GET /audit-log` (paginated, parses log_entries.raw)
  - `GET /dashboard-stats` (rollup)
  - `GET /public-ip-self` (detector status)
- **`crowdsec.Client.DeleteDecisionByID`**: per-row unban for
  the v1.3.24 Banned IPs tab. 404 mapped to idempotent
  "already gone".
- **`security.WhitelistEntry`**, `ListWhitelist`,
  `DeleteWhitelistByID`. The delete also rewrites the
  shared sentinel for setup-appsec.sh.

### Changed

- **SelfBlockBanner is now v2**. Multi-IP rendering with
  per-IP rows (current_session / public_ip / active_session
  source labels), per-IP unban + whitelist actions,
  count-aware headline. Backwards-compat: pre-v1.3.23
  panels (no `banned_ips` field in response) fall back to
  the v1.3.19 single-IP shape.

### Smoke gate

Per the working agreement (smoke verifies effect, not specs):

- Operator-visible effect: ban operator's LAN IP via cscli,
  banner v2 row appears under "this session" source, click
  Unban -> 200 + cscli decisions list returns empty.
- Same for public IP (after first ipify poll).
- Audit row in log_entries carries _source_ip + _xff_chain.
- Multi-IP: two browsers different networks, ban one,
  banner identifies the specific IP.
- NO tag until smoke real PASSes against prod stack.

### Not in v1.3.23

Deferred to v1.3.24:
- /security UI tabs (Banned IPs / Whitelist / Activity)
- Dashboard widget on /dashboard-stats
- Scenarios management UI, AppSec threshold tuning UI

## [1.3.22] - 2026-04-25

Two-bug release: v1.3.21 country expansion shipped with two
latent upstream-behaviour bugs that only became visible when
the operator exercised the lifecycle end-to-end against real
LAPI (Apr 25 2026 prod-smoke). See
docs/release-notes/v1.3.22.md for the full upstream-source
citations and empirical numbers.

### Fixed

- **Revoke now uses the singular `origin=` filter on DELETE.**
  LAPI's GET handler accepts `origins=` (plural, multi-value
  list filter); the DELETE handler only accepts `origin=`
  (singular, single-value EQ). v1.3.21 sent the plural form
  and Revoke silently failed with HTTP 500
  `'origins' doesn't exist: invalid filter`. Permalinks to
  the upstream pkg/database/decisions.go in the source
  comment.
- **Country expansion now uses a supernet rollup architecture
  to avoid LAPI silent-drop on bulk inserts.** v1.3.21 looped
  one /v1/alerts POST per CIDR; v1.3.22's first iteration
  batched 21k+ alerts into one POST. BOTH approaches hit a
  silent failure: LAPI's bulk insert is NOT atomic at scale,
  and SQLite WAL lock contention dropped most entries with
  201 Created returned to the client. Verified in prod:
  21,521 inserts requested -> 5,001 IPv6-only persisted ->
  zero IPv4 -> BR test IPs not enforced.

  The fix is architectural: the panel-side rollup
  (RollupToSupernets) compresses the MMDB output to <= 200
  supernets where possible, with /16 (v4) and /28 (v6)
  floors that prevent over-blocking neighbouring address
  space. Most countries fit comfortably under 200; fragmented
  allocations like BR / IN need ~3-5k entries at the floor.
  All entries land atomically in chunked /v1/alerts batches
  (chunk_size=500, ~12 chunks for BR, ~25s total).

### Added

- **`country.RollupToSupernets(cidrs, target)`** -- new file
  backend/internal/security/country/rollup.go. Family-aware
  per-CIDR aggregation with a hard floor on supernet width.
  7 unit tests cover small-input passthrough, adjacent-prefix
  collapse, coverage invariant, BR-size simulation, v4/v6
  split, empty input, malformed input, and the v4-floor
  regression lock.
- **`crowdsec.Client.AddRangeDecisions(ctx, []input)`** --
  batch method for Range decisions. Used by the country
  expander; called once per chunk.
- **`crowdsec.Client.WriteHTTP`** -- separate http.Client
  with a 5-min ceiling for batch writes. The default
  `HTTP` keeps its 10s ceiling for short reads.
- **`crowdsec.Client.ListDecisionsByScope`** -- bouncer-key-
  authenticated GET filtered by scope. Supports the
  startup legacy-detection scan.
- **`Expander.ChunkSize` field** -- tests override; production
  uses DefaultChunkSize=500.
- **Frontend partial-failure toast** -- the Settings UI
  surfaces "added BR: 4500 of 5009 CIDR ranges committed
  (1 chunks failed -- retry to fill in)" when failed_chunks
  > 0. Submit button label updated to set expectations on
  larger countries.

### Changed

- **`Expander.Ban` is now a chunked + continue-on-error loop.**
  Each chunk is one /v1/alerts POST. A failed chunk is logged
  + skipped; subsequent chunks proceed. The persisted tracking
  row reflects only the COMMITTED CIDRs; the API response
  surfaces failed_chunks separately so the operator can retry.
- **`MMDBSource.ListCIDRs`** runs the raw MMDB iteration
  through RollupToSupernets before returning. The raw path is
  intentionally not exposed -- v1.3.22 prod-smoke proved the
  raw set is incompatible with LAPI's write-throughput.
- **Panel http.Server.WriteTimeout** raised from 30s to 20min.
  The country-expansion handler is the only path that needs
  the headroom; v1.3.23's async background-job path will
  let us drop it back.

### Tests

- 11 country-expander tests (9 carryover + 2 new chunking).
- 7 rollup tests including the v4-floor regression lock.
- 3 crowdsec-client tests (singular-origin fix + batch
  emit + empty-input no-op).
- All 21 backend test packages still green.

### Smoke

scripts/smoke/country-block.sh PASSes against the v1.3.22
prod stack. Per-IP enforcement: 4/4 BR test IPs return 403
(146.70.98.104, 149.102.251.103, 200.221.2.45, 177.10.0.1).
Negative controls: 8.8.8.8 and 1.1.1.1 (both US) return
302. BR re-expansion completes in 25s end-to-end, 5009
supernets persisted, 0 failed_chunks.

### The four-strike upstream-behaviour pattern

v1.3.18 / v1.3.20 / v1.3.22 (BUG-2) / v1.3.22 (BUG-3) all
share the failure mode: bugs that pass unit tests with fakes
but fail against real upstream. Working agreement update
(memorised): smoke verifies EFFECT (per-IP enforcement),
unit tests verify EMIT. Both are necessary; only smoke
catches upstream-behaviour bugs. See release notes for the
full table and lesson.

### Not changed

- DB schema (migration 029 still latest).
- API endpoint shapes
  (POST/GET/DELETE /api/security/countries/* unchanged).
- v1.3.20 `enable_streaming: false` emit (required for any
  non-IP scope).
- v1.3.19 self-block banner, whitelist lifecycle, dormant
  hosts.true_detect_mode column.

## [1.3.21] - 2026-04-25

The honest fix v1.3.20 was missing. Country geo-blocking
now actually enforces.

### Fixed

- **Country bans actually enforce at the Caddy edge.** The
  panel translates one operator-issued country ban into N
  scope=Range LAPI decisions (the upstream
  hslatman/caddy-crowdsec-bouncer plugin does not handle
  scope=Country in either stream or live mode -- v1.3.20
  documented the upstream gap; v1.3.21 ships the
  architecturally correct workaround). Each decision is
  tagged origin=argos-country-XX so revocation is a single
  DELETE /v1/decisions?origins=... call.

### Added

- **Migration 029**: `country_ban_expansions` table.
  Tracks country_code, JSON array of CIDR strings, MMDB
  version at creation time, audit metadata. UNIQUE
  constraint on country_code -- re-banning the same
  country replaces the existing expansion atomically.
- **`backend/internal/security/country` package** with
  Expander.Ban / Revoke / List operations. CIDR source is
  an interface; production uses the embedded MMDB the
  geoip enrichment feature already ships.
- **Three new endpoints**:
  - `POST /api/security/countries/expand`
  - `GET  /api/security/countries`
  - `DELETE /api/security/countries/{cc}`
  All audit-logged. Behind the same session middleware as
  the rest of /api/*.
- **`crowdsec.AddRangeDecision`** -- the Range-scope sibling
  of the existing AddDecision (which was IP-only). Same
  /v1/alerts envelope, scope=Range.
- **`crowdsec.DeleteDecisionsByOrigin`** -- single LAPI call
  to drop every decision tagged with a given origin.
- **`crowdsec.ListDecisionsByScope`** -- bouncer-key-
  authenticated GET, used by the legacy-detection scan.
- **Startup legacy-detection warning** -- on panel boot,
  any active scope=Country LAPI decision logs a slog.Warn
  with a hint to convert via the new expand endpoint. NOT
  auto-converted: the operator decides which legacy bans
  matter.
- **Settings page UI**: new "Country bans (expanded)"
  section between "DNS providers" and "Logs". Inline form
  + table with revoke button. Minimum viable; richer UI
  (flag picker, heatmap) queued for v1.3.22.

### Tests

- 9 unit tests on Expander (happy-path, code validation,
  unknown-country, replace-on-conflict, partial-failure
  unwind, revoke happy-path, revoke missing, list ordering,
  case insensitivity).
- Migration 029 forward-shape + UNIQUE constraint
  (`TestMigration029CountryBanExpansions`).
- Migration 029 rollback in the chained test.
- All existing crowdsec / api / db tests still green.

### Smoke gate

`scripts/smoke/country-block.sh` PASSes on v1.3.21 stacks
AFTER the operator converts a test country via the expand
endpoint. The script header documents the release-by-release
expected result. Working agreement: the live-stack smoke is
the oracle for upstream-behavior fixes; unit tests prove
emit, smoke proves enforcement.

### Documentation

- `docs/release-notes/v1.3.21.md` (this release).
- `docs/operations/access-control.md` -- country-blocking
  section rewritten to describe the expansion mechanism +
  the new endpoints. Old "doesn't work" callout collapsed
  into a "v1.3.21+ required" reminder.
- `docs/release-notes/v1.3.20.md` -- "Fixed in v1.3.21"
  banner above the existing incomplete-fix note.

### Trade-offs

- CIDR list size scales with country: a few entries for
  small countries, 500-1500 for large ones. Trivial for the
  bouncer's radix tree.
- MMDB age affects accuracy at expansion time. The
  `mmdb_version_at_creation` column anchors a future
  reconcile pass (queued for v1.3.22) that adopts CIDR
  changes from monthly MMDB refreshes.
- v1.3.20's `enable_streaming: false` flag stays in place;
  v1.3.21 inherits the per-request LAPI roundtrip.
- No country-whitelist mode (allow X, Y only). Same upstream
  gap on the allow side; defer.

### Not changed

- Migration 028 schema (true_detect_mode dormant column,
  security_whitelist), v1.3.19 self-block banner, v1.3.18
  lan_only -- all untouched.
- No env var, no compose surface, no version of any
  third-party dep changed.

## [1.3.20] - 2026-04-25 -- INCOMPLETE FIX

> **Post-merge investigation (Apr 25 2026, same day) confirmed
> this release does NOT actually fix country geo-blocking.**
> The `enable_streaming: false` flag lands in the runtime
> Caddy config, but the upstream `hslatman/caddy-crowdsec-bouncer`
> plugin does not handle `scope=Country` in either stream OR
> live mode (verified against plugin commit `f1e77b2`,
> [store.go L43-L58](https://github.com/hslatman/caddy-crowdsec-bouncer/blob/f1e77b2d4497f6bd512660dd1338e2ad291a5210/internal/core/store.go#L43-L58)
> + live-mode `IPEquals`-only LAPI query). Country bans have
> NOT been functional in any v1.3.x release. The test suite
> shipped here verifies the emit, not the upstream behavior --
> the bug is a category of test that did not exist before.
>
> v1.3.21 will resolve this by expanding Country bans into
> equivalent Range decisions panel-side. See
> `docs/planning/v1.3.21-country-expansion.md` and
> `docs/release-notes/v1.3.20.md` for the full upstream-source
> citation.
>
> **v1.3.20 is pushed to main but NOT tagged** -- treat this
> entry as a milestone marker, not a release.

### Attempted fix (insufficient)

- **`enable_streaming: false`** now emitted in the panel-
  generated Caddy crowdsec block. Lands in runtime config but
  does not resolve the country-blocking failure on its own. The panel-emitted Caddy bouncer block now sets
  `enable_streaming: false` explicitly. Pre-v1.3.20 stacks
  let the plugin default to `true` (stream mode), which only
  indexes scope=Ip / scope=Range; Country bans were active in
  CrowdSec but ignored at the Caddy edge -- requests returned
  200/304 instead of 403. Verified Apr 25 2026 with a real
  request from a BR-resolving IP: HTTP 304 despite Country=BR
  active.

  Trade-off: per-request LAPI roundtrip replaces in-memory
  index lookup. The bouncer's in-process cache absorbs the
  steady-state cost; for homelab traffic shapes the latency
  delta is noise. v1.3.21 may surface streamMode as a
  Settings toggle if a workload genuinely needs the
  performance and is willing to give up non-IP scopes.

### Added

- **`scripts/smoke/country-block.sh`** -- end-to-end
  verification script. Adds a Country decision via cscli,
  probes the live stack with `X-Forwarded-For` spoofing an
  IP that GeoLite2 resolves to that country, asserts a 403,
  cleans up. Refuses to run with placeholder defaults so a
  bare invocation cannot silently pretend to verify nothing.
  Intended to run after every change to the caddycfg
  crowdsec emit path.

### Tests

- `TestCrowdSecEmitsEnableStreamingFalse` -- the panel emit
  must include the flag with value `false`.
- `TestCrowdSecEmitsEnableStreamingFalseWithAppSec` -- the
  flag must be emitted regardless of AppSec wiring (the bug
  is independent of AppSec mode).
- `TestCrowdSecBouncerEmitMaintainsTickerInterval` --
  no-regression assertion. The v1.3.20 emit change must not
  drop or rename `ticker_interval`.

### Documentation

- **`docs/operations/access-control.md`** -- pre-v1.3.20
  silent-failure callout in the Country-based blocking
  section + reference to the smoke script.
- **`docs/release-notes/v1.3.19.md`** -- known-limitation
  entry marking this release as the fix.
- **`docs/release-notes/v1.3.20.md`** (this release).

### Not changed

- v1.3.19's AppSec sane defaults, self-block banner,
  whitelist lifecycle, migration 028 schema -- all untouched.
- The dormant `hosts.true_detect_mode` column remains
  dormant; per-host enforcement queued for v1.3.21 alongside
  SelfBlockBanner v2 + audit log work.

## [1.3.19] - 2026-04-25

Closes the recurring v1.3.x dogfood failure: argos's own
AppSec stack auto-banning the operator's IP off legitimate
realtime traffic. Three concrete shifts: sane defaults
out of the box, a self-block escape hatch banner in the
panel, and a panel-managed whitelist that survives
restarts.

### Added

- **`hosts.true_detect_mode` column** (migration 028,
  dormant). Schema-only forward-compat hook; UI exposure
  and enforcement deferred to v1.3.20 due to an upstream
  CrowdSec v1.6.3 limitation (profile filters cannot
  reference target host: `Alert.Meta` does not include
  it). v1.3.20 will use per-host `appsec_config` selection
  via Caddy template.
- **`security_whitelist` table** (migration 028). Source
  of truth for panel-managed whitelist entries; partitions
  into `ip:` vs `cidr:` lists when emitted.
- **Three minimal `/api/security/*` endpoints** behind the
  existing session middleware:
  - `GET /api/security/check-self` -- returns the caller's
    resolved IP + active LAPI decisions (uses LAPI's
    `?ip=` filter so a CAPI-blocklist-enabled stack does
    not drown the response).
  - `POST /api/security/decisions/unban-ip` -- drops every
    active decision for the supplied IP via LAPI
    `DELETE /v1/decisions`.
  - `POST /api/security/whitelist` -- persists a row in
    `security_whitelist` and rewrites the panel sentinel
    file at `/data/shared/argos-whitelist-entries.txt`.
    Surfaces the exact `setup-appsec.sh` reload command
    in the response.
- **`SelfBlockBanner` component** mounted in `Layout.tsx`
  (visible on every panel page). Polls `check-self` every
  60s; when the operator's IP is banned, surfaces "Unban
  my IP", "Whitelist my IP permanently", and "Dismiss this
  session" actions.
- **`crowdsec.ListDecisionsByIP`** -- IP-filtered LAPI
  call to bound response size on stacks with large CAPI
  blocklists. Fixes silent JSON-decode truncation that
  made `check-self` return `banned=false` despite an
  active decision.
- **Panel-managed argos whitelist parser**:
  `setup-appsec.sh` writes
  `/etc/crowdsec/parsers/s02-enrich/argos-whitelist.yaml`
  with system ranges (RFC 1918 / loopback / ULA) hard-coded
  + operator entries from `security_whitelist`.
- **`argos/tuning` local SecLang rule pack** at
  `crowdsec/appsec-rules/argos-tuning.yaml`. Bumps
  `tx.inbound_anomaly_score_threshold` from CRS default 5
  to 15. Loaded inband by both block and detect AppSec
  configs.

### Changed

- **AppSec defaults out of the box (v1.3.19 reset)**:
  - `crowdsecurity/appsec-native` and
    `crowdsecurity/appsec-generic-test` are now removed
    on every `setup-appsec.sh` run. Both convert single
    inband WAF alerts into LAPI bans -- too aggressive
    for homelab traffic. Operators wanting the vendor
    posture can re-install them with `cscli scenarios
    install ...`.
  - `RemoveInBandRuleByID(920420)` now in `on_load` for
    both `argos-appsec-block.yaml` and
    `argos-appsec-detect.yaml`. CRS rule 920420 enforces
    a `Content-Type` whitelist that excludes `text/plain`,
    which socket.io polling and several monitoring tools
    legitimately use. Rule still loads outofband (visible
    in detection metrics).
- **Reconciler** now writes `argos-whitelist-entries.txt`
  and `argos-true-detect-hosts.txt` to `/data/shared` on
  every successful Caddy load.
- **`docker-compose.yml`**: `argos_shared_setup` volume now
  also mounted into the long-running `crowdsec` service
  as `/shared` (was previously only on `crowdsec-init`).
  `crowdsec/appsec-rules/` mounted at `/setup/appsec-rules`
  for `argos-tuning.yaml` to be copied into place.

### Documentation

- **`docs/features/appsec.md`** -- four new sections:
  "Detect mode is NOT 'no-block'" (mode table + scenario
  cascade + v1.3.20 roadmap note with upstream-source
  citation), "Tuning rationale", "Scenarios: homelab vs
  enterprise posture", "Common false positives" table.
- **`docs/release-notes/v1.3.19.md`** (this release).

### Not changed

- v1.3.18's `lan_only` per host, v1.3.16's
  `preserve_host`, v1.3.14's `transport.versions`, target
  health badges, CLI password reset -- all untouched.
- No env var, no compose surface change beyond the new
  shared volume mount on the `crowdsec` service.

## [1.3.18] - 2026-04-25

Closes the v1.3.17 access-control deferral: the per-host
"LAN-only" toggle that v1.3.17 documented as roadmap is now
implemented natively in argos.

### Added

- **`hosts.lan_only` column** (migration 027). Default 0
  (false). Idempotent up + down.
- **Per-host LAN-only Caddy gate** -- when `lan_only=true`
  for a host, the panel emits a gate route at the front of
  the per-host subroute that matches every PUBLIC source IP
  (NOT in `127.0.0.0/8`, `::1/128`, `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) and serves
  a `403 Access denied` terminally. LAN / VPN / loopback
  clients fall through to the existing chain unchanged.
- **API**: `POST /api/hosts` and `PUT /api/hosts/{id}`
  accept an optional `lan_only` boolean (default false on
  create; preserves current value when omitted on update).
  `GET /api/hosts` returns the field.
- **UI**: new "Access" section in the Edit Host modal,
  positioned before "Advanced". Single checkbox "LAN-only
  access (block requests from public IPs)" with a tooltip
  spelling out the typical use cases (admin panels exposed
  via DNS but private) and the trusted_proxies caveat for
  multi-hop deployments. Hosts list shows an amber `LAN`
  badge next to the domain when the toggle is on so private
  hosts are spottable at a glance.

### Tests

- `TestLanOnlyEmitsGateRouteFirst` -- gate is the first
  inner route, uses `client_ip` (NOT `remote_ip`) so
  trusted_proxies-resolved IP drives the decision, includes
  every expected RFC 1918 / loopback / ULA range, serves 403,
  marked terminal.
- `TestLanOnlyFalseOmitsGate` -- existing hosts with
  default false continue to emit a single default route, no
  gate prepended (regression-locks the migration's "no
  behaviour change on upgrade" promise).
- `TestRollbackLastMigration` extended to roll back 027
  first (asserts `hosts.lan_only` is dropped) before
  reaching the existing 026 invariants.

### Critical implementation note: `client_ip` vs `remote_ip`

The gate's matcher is **`client_ip`**, not `remote_ip`.
Caddy v2.7+ removed the `forwarded` option from
`remote_ip` and split client-IP matching into a separate
`client_ip` matcher. `remote_ip` only matches the raw TCP
peer (always the trusted Docker bridge / loopback in argos's
deployment), which would let any public XFF-supplied client
slip past the gate. `client_ip` honours the same
trusted_proxies chain Caddy already uses for access-log
client_ip + the v1.3.8 ALPN / forwarded-host plumbing.

### Smoke

```text
mode: lan_only=1, host=<test-host>
- LAN client (loopback)        -> HTTP 200  (gate skipped)
- Public IP via XFF=8.8.8.8    -> HTTP 403  + body
                                  "Access denied: this host is
                                  restricted to local network"
- Restore lan_only=0           -> HTTP 200  (gate removed)
```

### Docs

- `docs/operations/access-control.md` -- "IP allowlist
  (LAN-only access)" section reordered: Approach A is now
  "Use argos LAN-only toggle (v1.3.18+)" with the full
  recipe + the trusted_proxies caveat for multi-hop
  deployments. Approach B is the firewall path (was A).
  Approach C is the CrowdSec scenario fallback (was B).
- `docs/operations/troubleshooting.md` -- "Why is my host
  reachable from the internet?" updated to point at the
  new toggle. New entry "Host with `lan_only=true` returns
  403 from inside the LAN" covering the trusted_proxies
  misconfiguration case + diagnostic.

### Not changed

- v1.3.16's `preserve_host`, v1.3.14's
  `transport.versions`, AppSec wiring, target-health
  badges, CLI password reset -- all untouched.
- No env var, no compose surface, no admin API contract
  changes.

## [1.3.17] - 2026-04-25

Docs-only release. No code, no schema, no compose changes.

### Added

- **`docs/operations/access-control.md`** -- new operator
  guide. Covers two access-control patterns that argos doesn't
  expose as first-class UI knobs but that the bundled CrowdSec
  sidecar already implements:
    - **Country-based blocking (geo-blocking).** Recipe via
      `cscli decisions add --scope Country --value <ISO>`.
      Notes the GeoLite2 ships with CrowdSec (no extra
      collection install), the ~15 s bouncer-poll propagation
      window, the audit surface in the panel Threats tab.
    - **IP allowlist (LAN-only).** Three approaches in
      recommended order: firewall at the router (cleanest,
      doesn't touch argos), CrowdSec range-whitelist via
      custom scenario (non-trivial, mostly an escape hatch),
      and waiting for the native per-host toggle that's on
      the roadmap.
  Includes a migration cheat-sheet table mapping
  Zoraxy / NPM / Traefik features to argos equivalents
  (single-IP / range / country / user-agent / path / WAF).
- **Cross-link from `docs/features/appsec.md`** -- "Related"
  section now points at the access-control guide so operators
  reading the AppSec page can find the bouncer-side decisions
  recipe.
- **Cross-link from `docs/operations/troubleshooting.md`** --
  two new short entries pointing at the access-control guide:
  "Why is my host reachable from the internet? (LAN-only
  intent)" and "Traffic from a country I want blocked still
  reaches the host".
- **`mkdocs.yml`** -- new "Access control" entry under the
  Operations section.

### Not changed

- No code, no migrations, no env vars, no compose surface.
  Behaviour identical to v1.3.16.

## [1.3.16] - 2026-04-25

### Added

- **Per-target-group `preserve_host` toggle** -- forwards the
  original `Host` header to upstream when enabled. Required by
  backends that bind sessions, WebSocket auth, or virtual-host
  routing to the request hostname (UniFi Network Controller is
  the canonical case). Caddy's reverse_proxy default uses the
  dialed `<host:port>` as Host, which most homelab backends
  tolerate but a sizeable minority do not. v1.3.14 unblocked
  HTTP/2-vs-HTTP/1.1 negotiation for WS; this release closes
  the second gap.
- **DB column** `target_groups.preserve_host` (migration 026,
  `INTEGER NOT NULL DEFAULT 0`). Default false preserves
  pre-v1.3.16 behaviour for every existing target group on
  upgrade -- the toggle is opt-in.
- **Caddy emit** -- when `preserve_host=true`, the
  reverse_proxy block gains
  `headers.request.set.Host: ["{http.request.host}"]`.
- **API** -- `target_groups` create/update endpoints accept an
  optional `preserve_host` boolean; default false.
- **UI** -- the Edit Target Group modal grows a
  `Preserve Host header (forward original hostname)` checkbox
  next to the existing `Verify upstream TLS certificate`
  toggle. Tooltip names the typical backends (UniFi NCP, auth
  proxies, virtual-hosted apps) and the diagnostic ("works on
  direct access but breaks behind argos").

### Tests

- 3 new tests in `internal/caddycfg/transport_test.go`:
  preserve_host=true emits the header forwarding block;
  preserve_host=false omits the headers block (no regression
  for existing target groups); preserve_host=true coexists
  with HTTPS upstream + verify_tls=false without field
  collision.
- `internal/db/migrate_test.go` -- rollback test extended to
  cover migration 026 first, then preserves the existing 025
  invariant (helper `tableHasColumn` extracted; the prior
  hosts-only `hostsHasColumn` becomes a thin wrapper).

### Docs

- New `docs/operations/troubleshooting.md` entry: "Backend
  works on direct access but breaks behind argos (UniFi, auth
  proxies)". Symptom catalog (WS 500, broken sessions,
  redirect-loop login, virtual-host mismatch), the
  `/etc/hosts`-based diagnostic, the fix, and a non-exhaustive
  list of known affected backends (UniFi NCP, Authentik /
  Authelia with specific configs, Mastodon / Misskey /
  GoToSocial / Synapse, Gitea / Forgejo with strict CSRF).

### Smoke

Verified end-to-end against the real prod stack: enabling
preserve_host on a target group via SQL update + reconcile
emitted the header-forwarding block in Caddy admin config;
disabling restored the default empty headers shape; regular
HTTP traffic flowed through both states (302 / 200 unchanged).

### Not changed

- v1.3.14's `transport.versions: ["1.1", "2"]` is unchanged --
  preserve_host is independent of WebSocket transport
  negotiation; both are needed for the UniFi NCP shape (one
  unblocks the WS upgrade, the other unblocks the
  hostname-bound auth check).
- Block-mode CRS coverage and v1.3.12's mode-swap
  attribution: untouched.
- No env var, no compose surface, no admin API behaviour
  changed.

## [1.3.15] - 2026-04-25

Security / hygiene patch. Scrubs operator-specific data that
the v1.3.2 - v1.3.14 dogfood pass leaked into committed release
notes, CHANGELOG, and a small set of code fixtures, then adds a
guardrail to keep it out.

### Changed

- **Sanitized private homelab subdomains** in tracked sources.
  Every per-service subdomain rooted at the maintainer's apex
  (smoke-test examples for media, IoT, network controller, etc.)
  was remapped to RFC 2606 placeholders rooted at example.com.
  Affected files: CHANGELOG.md, 8 `docs/release-notes/*.md`, 2
  docs files (phase1-dns and ARCHITECTURE), 1 frontend hint
  string (`SSOSection.tsx`), and 2 Go test files
  (`oidc_test.go`, `target_health_test.go`).
- **Sanitized operator LAN IPs** to RFC 5737 documentation
  ranges. Last octet preserved so distinct hosts in examples
  stay visually distinct. Affected files: 1 doc, 1 release
  note, 2 Go test fixtures, 1 notification-event template
  (`notifications/events.go`).
- **Sanitized one Go comment** that referenced the apex domain
  as an inline example for the `CookieParentDomain` field
  (`internal/oidc/config.go`).

### Added

- **`scripts/check-no-personal-data.sh`** -- CI guardrail.
  Scans tracked sources for three regression patterns (the
  maintainer's homelab apex + per-service subdomains, the two
  /24 prefixes from the smoke-test environment, and the
  maintainer's gmail handle when it appears outside the
  immutable commit-author column). Exits non-zero if any
  appear. The full regex set lives in the script itself; see
  `docs/CONTRIBUTING.md` for the documented exceptions
  (public Go module path, docs portal URL, mkdocs publisher
  attribution -- all preserved by design).
- **`.github/workflows/personal-data-guardrail.yml`** -- runs
  the script on every PR and push to main.
- **`docs/CONTRIBUTING.md`** -- new file. Documents the
  placeholder conventions (RFC 2606 / RFC 5737 references)
  plus the explicit list of operator-specific tokens that are
  preserved by design (Go module path, docs URL, mkdocs
  config). Excluded from the published mkdocs site (it's a
  contributor-facing doc, not operator-facing).

### Not changed

- **Commit history.** All `git log` references to the
  maintainer's email and the original homelab subdomains are
  preserved. Rewriting history would break already-published
  GitHub release tags and the bookmarks/CI integrations
  pointing at them; the privacy benefit of scrubbing past
  commits is outweighed by the disruption.
- **GitHub release bodies.** The release notes published at
  `github.com/cmos486/argos-edge/releases/tag/v1.3.X` are
  generated from the operator's editor session, not from the
  committed `docs/release-notes/v1.3.X.md` files. The
  maintainer must re-edit them manually after this release;
  see the v1.3.15 release notes for the exact list.
- **Public attribution.** `mkdocs.yml site_author: cmos486`,
  `repo_url: github.com/cmos486/argos-edge`, README badges,
  and Go module imports stay as they are -- the
  GitHub-handle-as-publisher mapping is the URL anyone reaches
  the project through and is not considered a leak.

## [1.3.14] - 2026-04-25

### Fixed

- **WebSocket upgrades on HTTPS upstreams now work.** Pre-v1.3.14
  the Caddy reverse_proxy emit set `transport.protocol: "http"`
  for HTTPS upstreams without an explicit `versions` field, and
  emitted no transport at all for HTTP upstreams. Caddy's
  default ALPN negotiation preferred HTTP/2 to HTTPS upstreams;
  classic RFC 6455 WebSocket upgrades cannot ride an HTTP/2
  connection (RFC 8441's WS-over-h2 is rarely implemented by
  typical backends). Result: realtime features broke on every
  HTTPS-upstream backend that uses WebSockets -- UniFi Network
  Control Plane was the reproducing case (`/api/ws/system` ->
  `500`, dashboards blank), with the same shape applying to
  any SPA that uses WS for realtime (Home Assistant when on
  HTTPS, Jellyfin streaming, n8n editor, Vaultwarden Send,
  ...).
- v1.3.14 emits `transport.versions: ["1.1", "2"]` on every
  reverse_proxy. HTTP/1.1 first keeps the WS upgrade path
  compatible; HTTP/2 stays available for non-WS traffic when
  the upstream advertises it via ALPN. Plain-HTTP upstreams
  also gain the explicit transport block (no behaviour change
  -- Go's `http.Transport` doesn't do h2c without TLS so the
  `"2"` entry is a no-op there).

### Tests

- 3 new tests in
  `backend/internal/caddycfg/transport_test.go`: HTTPS
  upstream emits `transport.versions` starting with `1.1` and
  preserves the TLS sub-block; HTTP upstream emits the same
  versions list and crucially NO TLS sub-block;
  `verify_tls=false` produces `insecure_skip_verify=true`.
  Locks the JSON shape against future regression.

### Smoke

Verified live in prod with Home Assistant (HTTP upstream) on
the new build:

```
$ curl -i -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
       -H 'Sec-WebSocket-Version: 13' \
       -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
       http://iot.example.com/api/websocket
HTTP/1.1 101 Switching Protocols
...
```

Plain-HTTP backends (no regression) and HTTP/302 backends
(no regression) both verified.

### Docs

- New `docs/operations/troubleshooting.md` entry: "WebSocket
  backend shows blank UI / connection errors (fixed in
  v1.3.14)" -- symptom catalog, the curl-based verify
  command, and the three escalation paths if a backend still
  fails post-fix (subprotocol mismatch, missing
  `X-Forwarded-Host`, transport not actually loaded by Caddy).

## [1.3.13] - 2026-04-25

UX patch: better validation message on `health_check_expect_status`
mixed-class input.

### Fixed

- **`health_check_expect_status` mixed-class validation message
  is now actionable.** Pre-v1.3.13 the rejection read
  `"cannot mix different status classes (e.g. 200,301): caddy's
  JSON active check only supports a single exact code or a 1xx-5xx
  class. Use a single code, a single class range, or create
  separate target groups."` -- technically correct, operationally
  useless. Operators trying to express "Plex returns 200 to /
  but 401 to anything else" got stuck without obvious next steps.
  The message now lists the three legal input shapes (single
  code, comma list within one class, numeric range within one
  class) and the four standard workarounds (single most
  representative code, same-class widening, switch to a
  consistent health-check path with examples per backend, or
  disable active checks). Includes a deep link to the
  troubleshooting doc for the full per-backend cookbook.

### Docs

- New `docs/operations/troubleshooting.md` entry: "Health check
  expect status validation rejected". Tabulates the legal shapes
  and gives concrete `health_check_path=...` recipes for the
  homelab-typical backends: Plex (`/identity`), Jellyfin
  (`/System/Ping`), the \*arr stack (`/ping`), Jellyseerr /
  Overseerr (`/api/v1/status`), Nextcloud (`/status.php`), Home
  Assistant (`/manifest.json`), Vaultwarden (`/alive`).
- The earlier "unhealthy 302" entry now cross-links to the new
  one for the legal-shape reference.

### Tests

- 2 new tests in
  `backend/internal/api/target_groups_validation_test.go`
  covering: mixed-class rejection produces a message containing
  every actionable hint (regression test against future drift),
  and single-class inputs (`200`, `401`, `200,204`, `200-299`,
  `400-403`) still parse cleanly.

### Not changed

- The parser (`internal/caddycfg/expectstatus`) is unchanged --
  same legal grammar, same `SpansMultipleClasses` detection.
  This release only changes what the operator sees when their
  input is rejected.

## [1.3.12] - 2026-04-25

### Fixed

- **Bug A: block mode was not detecting OWASP attacks.** Block
  mode used the vendor `crowdsecurity/appsec-default` config,
  which deliberately omits `crowdsecurity/crs` from inband rules
  to avoid the CRS false-positive rate becoming user-visible
  403s. Argos detect mode added CRS in v1.3.10 once the
  SendAlert wiring was in place; block mode was the symmetric
  follow-up that v1.3.10 forgot. Result: SQLi / XSS / RCE / LFI
  attacks flowed through block mode untouched. v1.3.12
  introduces a local `argos/appsec-block` config that mirrors
  `argos/appsec-detect` but with `default_remediation: ban` so
  the same rule surface that detect logs becomes the rule
  surface block enforces. Smoke verification: 4 attack payloads
  → all `HTTP 403`; 1 legitimate request → `HTTP 200`.
- **Bug B: panel UI counter was retroactively reclassifying
  pre-swap detect hits as blocked after a detect → block mode
  flip.** `metrics.go` aggregated all alerts through a single
  `blocking := mode == "block"` boolean, so a window that
  contained 15 detect-mode hits and 0 block-mode hits would
  display as "Total: 15, Blocked: 15, Logged: 0" the moment the
  operator flipped to block. Fixed via per-alert classification:
    1. CrowdSec attached `decisions` array → blocked (ground
       truth from the LAPI bucket pipeline).
    2. Otherwise: compare alert timestamp to the persisted
       `appsec.last_mode_change_at` boundary; alerts older than
       it use the new `appsec.previous_mode` setting, alerts
       at-or-after use the current mode. block → blocked, else
       logged.
  The mode-toggle handler (`AppSecPatchMode`) now persists
  `appsec.previous_mode` alongside the existing `..._at` /
  `..._by` settings so the metrics path has the prior-mode
  value.

### Added

- **`crowdsec/appsec-configs/argos-appsec-block.yaml`** -- new
  block-mode appsec-config. References the same rule pool
  (`crs` inband + `vpatch-*` + `generic-*` + base) as the detect
  variant, with `on_match: SendAlert()` for both phases and
  `default_remediation: ban`. Lives next to
  `argos-appsec-detect.yaml`; both ship via `setup-appsec.sh`.
- **`Alert.Decisions []AlertDecision`** field +
  `Alert.WasBlocked()` helper in `internal/crowdsec/types.go`.
  Exposes the per-alert decisions array CrowdSec emits at the
  alert level so the metrics provider can use it as the
  authoritative blocked/logged signal where present.
- **`appsec.classifyOutcome()`** -- pure function used by
  `Provider.compute`. Implements the two-tier attribution.

### Tests

- 5 new tests in `internal/crowdsec/types_test.go` covering
  `WasBlocked()` against real CrowdSec alert payloads
  (block-mode ban, detect-mode empty array, missing field,
  captcha decision, multiple decisions).
- 8 new tests in `internal/appsec/metrics_test.go` covering
  `classifyOutcome` -- decision-wins, no-boundary fallback,
  detect→block historical preservation, block→detect reverse
  swap, disabled mode, exact-boundary timestamp, unparseable
  timestamp.

### Docs

- `docs/features/appsec.md` setup section updated to mention the
  new `argos/appsec-block` config alongside the detect variant.

## [1.3.11] - 2026-04-25

### Added

- **`argos user list`** -- print id / username / TOTP-status /
  password-status / created-at for every user row.
- **`argos user reset-password <user>`** -- update a user's
  bcrypt password hash directly from the CLI. Two modes:
    - **Interactive** (default): prompts for the new password
      twice with echo suppressed, requires the two reads to
      match.
    - **Non-interactive** (`--password <p>`): for scripts; the
      password leaks to shell history so prefer interactive
      whenever an operator is at a terminal.
  Writes an `audit / password_reset` row with `source: cli` so
  the change is visible in the panel's Logs tab once the
  operator logs back in. SQLite WAL mode lets the running panel
  serve while the CLI writes; new hash is picked up on the next
  login attempt with no restart required.
- **`argos --help` / `argos -h` / `argos help`** -- top-level
  usage banner listing every subcommand. Pre-v1.3.11 the binary
  silently fell through to `run()` for any unknown arg, which
  led to the "I see a server bind error, where's the CLI?"
  confusion that surfaced this whole feature.
- **`argos server`** -- explicit name for "start the HTTP
  server" (the default behaviour with no args). Useful for
  scripts that want to be self-documenting.

### Fixed

- **CLI flag parsing accepts the natural arg order**
  `argos user reset-password admin --password X` (positional
  before flags). Go's `flag.Parse` stops at the first non-flag
  arg by default, which would otherwise force the awkward
  flags-before-positional shape. Username is extracted before
  the FlagSet is invoked.

### Tests

- 8 new tests in `backend/cmd/argos/cli_user_test.go` covering:
  non-interactive reset, interactive match + mismatch, audit
  row insertion, short-password rejection, unknown user,
  blank-username rejection, ARGOS_DB_PATH requirement, and the
  natural-order arg parsing for `runUserResetPassword`.

### Docs

- `docs/operations/troubleshooting.md` "Forgot admin password"
  -- exact docker compose exec invocations for both modes,
  offline (panel-down) recovery via the same binary against the
  data volume, and a last-ditch sqlite3 + htpasswd fallback for
  cases where the image itself is broken.

### Dependency note

- `golang.org/x/term v0.28.0` is now a direct dep (was indirect
  via `golang.org/x/crypto`). Used for echo-suppressed reads on
  the interactive password prompt. `go mod tidy` also promoted
  `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2` from
  indirect to direct in the same pass -- they were already used
  by `internal/oidc/` but had stale metadata.

## [1.3.10] - 2026-04-25

### Fixed

- **`crowdsecurity/crs` now in detect-mode `inband_rules`.**
  Pre-v1.3.10 the detect config covered base-config + CVE
  vpatches + the small generic-rules set, but the OWASP Core
  Rule Set (which is where SQL injection / XSS / RCE / LFI /
  command-injection / PHP-injection signatures actually live)
  was installed in the rule pool but not referenced from the
  acquisition. Result: a payload that wasn't a CVE vpatch
  produced zero detection. v1.3.9 made detect mode emit alerts
  for the rules it was loading, but it was loading the wrong
  set of rules. v1.3.10 closes that gap.

  Block mode (`crowdsecurity/appsec-default`, vendor-shipped)
  is unchanged on purpose: the vendor keeps CRS out of inband
  block-mode because false-positive risk on legitimate traffic
  is non-trivial. argos detect mode is log-only, so the
  trade-off flips: false-positives just produce extra entries
  on the AppSec page, never a 403 to a real user.

### Verification

Same 10-payload smoke from
[features/appsec.md > Testing AppSec detection](docs/features/appsec.md):

| Payload class | Pre-v1.3.10 alerts | Post-v1.3.10 alerts |
|---|---|---|
| SQL injection x 2 | 0 | 2 (sql_injection 10 + 30) |
| XSS x 2 | 0 | 2 (xss 30 + 40) |
| Path traversal | 0 | 1 (lfi 55) |
| Command injection | 0 | 1 (lfi 10 + rce 20) |
| RCE eval | 0 | 1 (php_injection 10) |
| Log4shell JNDI | 0 | 1 (rce 5) |
| SSTI | 0 | 1 (lfi 5) |
| Total | 0 | 9 / 10 |

The 10th payload (WordPress wp-config.php.bak recon) doesn't
match a CRS signature and is best caught by request-flood
buckets at the LAPI layer; out of scope for this AppSec fix.

## [1.3.9] - 2026-04-25

Closes the v1.3.8 "investigated, not addressed" item:
detect-mode AppSec was silently dropping every alert.

### Fixed

- **`argos/appsec-detect` config now declares `on_match: SendAlert()`.**
  Pre-v1.3.9 the detect-mode appsec-config carried
  `default_remediation: allow` but no `on_match` hook. Tracing
  CrowdSec's `appsec_runner.go`: every request starts with
  `Response.SendAlert = true`, but the runner resets it to
  `false` at the inband -> outband boundary. Outband matches
  without an explicit `SendAlert()` therefore never reach the
  LAPI alert pipeline -- which is why `cscli alerts list` was
  empty and the panel's `total_hits` stayed at 0 forever
  regardless of payload. The vendor `crowdsecurity/crs` config
  carries the same directive (filtered to `IsOutBand`); argos's
  detect config was missing it. Both `IsInBand` and `IsOutBand`
  filters are now declared for symmetry.
- **Panel AppSec probes carry a User-Agent.** Once SendAlert()
  is wired the v1.3.8 envelope-headers fix exposed a
  consequential bug: the probes had no User-Agent, which made
  `crowdsecurity/experimental-no-user-agent` classify them as
  attacks every 30 s. Both probes now send
  `User-Agent: argos-panel/{healthcheck,probe}` and the
  matching `X-Crowdsec-Appsec-User-Agent` header. Net effect:
  zero false-positive alerts from panel internal traffic.

### Added

- **Docs: "Testing AppSec detection"** new section in
  `docs/features/appsec.md` -- 10 deliberately-benign payloads
  (no-UA, classic SQLi, sqlmap UA, path traversal, command
  injection, XSS, log4shell, SSRF, SSTI, CMS recon) operators
  can use to validate detection on their own deployment, plus
  the cscli + panel-metrics verification commands.
- **Troubleshooting**: new entry "Detect mode emits no alerts
  (fixed in v1.3.9)" with cause + upgrade path + stale-volume
  recovery for ops that pulled the new image but still see the
  old config in the shared_setup volume.

### Tests

- `appsec.TestPingSendsUserAgentHeaders` -- verifies both
  `User-Agent` and `X-Crowdsec-Appsec-User-Agent` reach the
  AppSec listener so the no-UA rule does not flag panel probes.

## [1.3.8] - 2026-04-25

AppSec log-spam fixes + defense-in-depth client-IP propagation.

### Fixed

- **Panel AppSec probes now send the AppSec request envelope.**
  Both `appsec.healthcheck` (every 5 min) and the Status-page
  `ProbeHub` (every 30 s) used to dial `:7423` with only the
  bouncer API key. CrowdSec validates the four envelope headers
  (`X-Crowdsec-Appsec-Ip` / `-Uri` / `-Verb` / `-Host`) before
  rule evaluation and logged
  `missing 'X-Crowdsec-Appsec-Ip' header` once per probe -- a
  steady drumbeat of 30-second errors that drowned out genuine WAF
  events. Probes now send synthetic-but-well-formed envelopes
  (loopback IP, well-known healthcheck path, GET, panel-local
  Host); CrowdSec accepts and replies `allow` cleanly with zero
  log output.

### Added

- **`trusted_proxies` config emitted on the Caddy main server**
  with RFC1918 + IPv4/IPv6 loopback + Docker bridge defaults, plus
  `client_ip_headers: ["X-Forwarded-For"]`. Pre-v1.3.8 Caddy was
  populating `caddyhttp.ClientIPVarKey` from `RemoteAddr`, which
  is correct in single-hop deployments but fails the moment a
  CDN / cloud LB / ingress-controller joins the chain in front of
  Caddy. The caddy-crowdsec-bouncer plugin reads
  `ClientIPVarKey` to build the `X-Crowdsec-Appsec-Ip` header it
  sends to AppSec, so making the var resolve correctly under both
  shapes closes the WAF-inline feature loop. Defense-in-depth: no
  current deployment is broken, but a Cloudflare-fronted argos
  would have lost its real-client-IP signal silently.

### Known issue (cosmetic, not regressed)

- **`conflicting id <N> for rule !` warnings on CrowdSec boot
  (~190 entries).** Argos installs two AppSec acquisitions so
  the bouncer can flip mode without a CrowdSec restart; both
  acquisitions reference the same rule collections, so the
  second-loaded one logs a conflict warning per rule. Functional
  impact: none -- the first-loaded copy stays effective. Fix
  options either regress the mode-toggle UX (CrowdSec reload on
  every change) or require operator intervention; deferred to a
  future release. Documented in
  `docs/operations/troubleshooting.md`.

### Investigated, not addressed

- "AppSec total_hits stays 0 after sending obvious payloads"
  reported in the Bug A filing was reproduced and traced. Real
  Caddy traffic IS reaching AppSec correctly (verified
  `client_ip` in access logs + direct `wget` against `:7422` /
  `:7423` from inside the caddy container). Rules ARE loaded
  (188 inband + 2 outofband, confirmed via
  `cscli appsec-rules list`). The reason `cscli alerts list`
  shows nothing on rule match is a CrowdSec-side question
  (`argos/appsec-detect` lacks an explicit `on_match: SendAlert()`
  directive that the vendor `crowdsec/crs` config has) and out
  of scope for this release. The panel-probe spam fix alone
  removes the misleading "missing IP header" symptom that was
  conflated with the alerts gap.

## [1.3.7] - 2026-04-24

Target health badges in the panel. Closes the v1.3.6 Bug 5 deferral:
the operator can now see per-target health state directly on the
Target group page instead of filtering Logs for caddy_error entries.

### Added

- **`GET /api/targets/health`** — returns every target with a
  derived `healthy` / `unhealthy` / `unknown` status plus the last
  HTTP status code, last error string, last-checked timestamp, and
  lifetime request / fail counters. Cached 30 s in memory; drops on
  the next mutation that triggers a reconcile so freshly-added
  targets land as `unknown` rather than stale data.
- **`caddy.Client.Upstreams`** — thin client for Caddy's
  `/reverse_proxy/upstreams` admin endpoint. Returns
  `{address, num_requests, fails}` per upstream pool entry.
- **`TargetHealthBadge`** component + Health column in the Target
  group detail page. Colour-coded badge (green/red/grey), inline
  hint (status code or truncated error), full tooltip on hover
  (timestamp + error + counters). Polls every 30 s while visible.
- **Docs**: new "Health monitoring" section in
  `features/reverse-proxy.md`; two new troubleshooting entries
  (`unhealthy 302` expected-status mismatch, `unknown` forever).

### Data source

Hybrid: Caddy admin API for live counters (authoritative for
`num_requests` / `fails`) plus a 90-second scan of the ingested
caddy_error log for `http.handlers.reverse_proxy.health_checker.active`
entries (source of `last_status_code` / `last_error` /
`last_checked_at`). The admin endpoint alone does not expose those
fields; the log tail was already in-process via the v1.0 ingestor
so no new file tail was added.

### Not changed

- No DB migrations. The endpoint reads existing `log_entries` rows.
- No changes to the v1.3.6 CrowdSec flow — bugs 1-4 from the
  previous release stay untouched.
- Bug 5 UX follow-up ("quick-action to edit expect-status from the
  badge") deferred to v1.3.8 per the filing; the current badge
  tooltip + troubleshooting entry cover the operator's need to
  diagnose.

## [1.3.6] - 2026-04-24

Bug-fix release addressing four issues surfaced operating the
v1.3.5 auto-bootstrap in production. Bug 5 from the filing
(target-group health badges) deferred to v1.3.7 — new API + UI
out of scope for this release.

### Fixed

- **Init container collision fallback now actually works** (bug 1).
  The v1.3.5 pre-check used a tight grep pattern
  (`"\"machineId\":\"argos-panel\""`) that never matched cscli's
  JSON output (`"machineId": "argos-panel"` — note the space).
  Collision detection silently passed, then `cscli machines add`
  failed with `user already exist` and the init exited 1. Replaced
  with a simpler try-add-catch-retry-with-timestamp-suffix that
  doesn't parse JSON at all.
- **Stale-credentials detection at boot** (bug 2). When stored
  machine credentials became invalid out-of-band (operator ran
  `cscli machines delete`, CrowdSec rotated its signing key,
  master key change corrupted ciphertext), the panel kept
  retrying forever and AppSec metrics kept returning
  `lapi 401: incorrect Username or Password`. New
  `crowdsec.VerifyMachineCredentials` probe runs once at boot;
  401 → purges settings via `PurgeMachineCredentials` + emits new
  `crowdsec_creds_stale` notification. Transient 5xx/timeout/dial
  errors do NOT trigger the purge (wouldn't want a LAPI hiccup to
  nuke working credentials).
- **Add-host modal now scrolls** when content exceeds viewport
  (bug 4). Pre-existing issue; forms with Advanced +
  inline-target-group + DNS-provider dropdown pushed Save
  off-screen on small viewports. `Modal.tsx` restructured to a
  flex-column layout with `max-h-[calc(100vh-2rem)]`, a
  non-shrinking header, and a `flex-1 overflow-y-auto` body. Save
  always reachable.

### Added

- **`POST /api/crowdsec/regenerate-credentials`** endpoint (bug 3).
  Operator-triggered stale-creds reset without needing to restart
  the panel. Verifies current creds against LAPI, purges on 401,
  returns one of four statuses (`valid` / `purged` /
  `no_credentials` / 502). Does NOT call docker compose from the
  panel — operator runs `docker compose up crowdsec-init`
  manually to regenerate.
- **Verify & regenerate credentials** button in the AppSec
  metrics-degraded banner. Invokes the new endpoint, toasts the
  resulting message. Updated banner copy to describe the v1.3.5
  auto-bootstrap flow.
- **New notification event `crowdsec_creds_stale`** (severity
  warning). Fires from both the boot probe path and the
  regenerate endpoint when credentials are purged.
- **Troubleshooting entries** for the init-collision symptom and
  the `crowdsec_creds_stale` event in
  [`docs/operations/troubleshooting.md`](docs/operations/troubleshooting.md).

### Not changed

- Env-var-sourced machine credentials are never auto-purged. The
  stale-creds probe only runs when credentials came from the DB.
- Docker socket is NOT mounted on the panel. The regenerate
  endpoint's response tells the operator to run
  `docker compose up crowdsec-init` manually.
- No DB migrations. Purge writes empty-string values; no schema
  change.
- `appsec.fail_open`, `appsec.mode`, AppSec healthcheck, DNS
  providers, everything else — unchanged.

### Deferred

- **Target health status in UI** (originally bug 5). New Caddy
  admin API endpoint + polling UI + badge component. Landing in
  v1.3.7.

## [1.3.5] - 2026-04-24

Follow-up to v1.3.4. v1.3.4 stopped the AppSec metrics page from
failing when machine credentials were missing; v1.3.5 removes the
missing-credentials condition entirely for fresh installs by
bootstrapping credentials automatically via a short-lived init
sidecar. See [release notes](docs/release-notes/v1.3.5.md) for the
full story + rollback path.

### Added

- **`crowdsec-init` sidecar service** in `docker-compose.yml`.
  Shares the `crowdsec` container's network namespace, runs
  `cscli machines add argos-panel --auto -f <shared-file>`, exits.
  Gated on CrowdSec being healthy. Idempotent: skips if the
  credentials file already exists or an existing `argos-panel`
  machine is registered (in which case it uses a timestamp
  suffix).
- **`argos_shared_setup` named volume**. Ephemeral handoff
  channel between the init sidecar and the panel. Safe to wipe;
  the init regenerates on next up.
- **`crowdsec.ImportMachineCredentials`** (backend). Reads the
  handoff YAML, encrypts the password under `ARGOS_MASTER_KEY`,
  writes settings, deletes the plaintext file. Idempotent on the
  missing-file, already-configured, and repeat-run paths. Non-
  fatal: failures log a warning and the panel continues booting,
  metrics fall back to the v1.3.4 degraded banner.
- **`crowdsec.ResolveMachinePassword`** helper. Prefers the new
  encrypted setting, falls back to the legacy plaintext setting.
  Main.go reads via this helper so the v1.3.4 and v1.3.5 settings
  paths resolve transparently.
- **New setting key**: `crowdsec.machine_password_encrypted`.
  Holds the argos1: ciphertext. Written by the bootstrap module,
  read by `ResolveMachinePassword`.

### Changed

- **Panel boot sequence**: `argos` service now depends on
  `crowdsec-init: service_completed_successfully` in addition to
  `crowdsec: service_healthy`. The init completes in a couple of
  seconds on fresh installs; on re-runs it exits immediately
  without touching LAPI.
- **Panel main.go** reads the machine password via
  `crowdsec.ResolveMachinePassword` instead of
  `getenvWithSetting(..., "crowdsec.machine_password", ...)`. Env
  vars still win; legacy plaintext setting still works as a
  fallback.
- **Docs**: AppSec feature page's "Panel metrics vs endpoint
  reachability" section rewritten to document the automatic
  bootstrap. Troubleshooting entry for the missing-metrics banner
  rewritten to list init-sidecar diagnostics first.

### Not changed

- No DB migrations. Settings table is the credentials' home.
- No UI changes. The degraded banner from v1.3.4 is still there;
  it just stops triggering on fresh installs.
- AppSec mode / fail_open / unavailable notification — all
  unchanged from v1.3.4.
- Caddy config generation / bouncer plugin — unchanged.

## [1.3.4] - 2026-04-24

Two bug fixes surfaced operating a real AppSec-enabled stack on
v1.3.3. See [release notes](docs/release-notes/v1.3.4.md) for the
full investigation + why the initial hypothesis about Caddy's
plugin was wrong.

### Fixed

- **Panel AppSec health probe now sends
  `X-Crowdsec-Appsec-Api-Key`**. Pre-v1.3.4 the probe (added in
  v1.3.2) hit `:7423` every 5 minutes with no auth headers, causing
  CrowdSec to log `missing API key` once per probe. Cosmetic
  issue — Caddy's own plugin auth was always correct — but
  alarming in the CrowdSec log. Probe now reads
  `CROWDSEC_BOUNCER_API_KEY` from the panel container env and
  forwards it on every request.
- **AppSec probe now treats 401 as its own class**. Old behaviour:
  silent pass (misclassified as healthy). New behaviour: surfaced
  as a config-mismatch error distinct from 404/5xx/network
  failures, so the operator can tell "auth mismatch" from
  "sidecar down".
- **Metrics endpoint gracefully degrades when machine credentials
  are missing**. Pre-v1.3.4 the UI failed the whole AppSec page
  with *"Could not load AppSec state: metrics from lapi: crowdsec
  not configured"*. That was misleading — the bouncer key alone
  is enough to run AppSec at request time, and `/v1/alerts` is
  the only thing that needs machine JWT. v1.3.4 returns a 200
  with a `degraded: {code, message}` field; the UI renders a
  scoped yellow banner in place of the charts while the status
  card above stays functional.

### Added

- `AppSecMetrics.degraded` field on the API response type
  (backend `internal/appsec/types.go`, frontend `api/client.ts`)
  carrying `{code, message}`. Code enum:
  `machine_credentials_missing`, `crowdsec_unreachable`,
  `lapi_error` (only the first is emitted today).
- `AppSecMetricsDegradedBanner` React component.

### Docs

- **New section**:
  [AppSec → Panel metrics vs endpoint reachability](docs/features/appsec.md#panel-metrics-vs-endpoint-reachability)
  explaining the bouncer-vs-machine credentials split and how to
  add machine credentials to unlock metrics.
- **Troubleshooting**: two new entries —
  [`CrowdSec logs: missing API key from the panel's IP every 5 minutes`](docs/operations/troubleshooting.md)
  and
  [`AppSec page shows "metrics unavailable: machine credentials missing"`](docs/operations/troubleshooting.md).

### Not changed

- Caddy's bouncer plugin is correctly sending the AppSec API key.
  No changes to `caddycfg` or the emitted Caddy config.
- No DB migrations; `degraded` is additive on the JSON response
  and old frontend builds ignore it harmlessly.
- `appsec.fail_open`, `appsec.mode`, and the `appsec_unavailable`
  notification event — all unchanged from v1.3.2 / v1.3.3.

## [1.3.3] - 2026-04-24

Docs-only patch. No code changes since v1.3.2.

### Added

- **New page: [AppSec (CrowdSec WAF-inline)](docs/features/appsec.md)**.
  The operator-facing entry point for the WAF-inline layer. Covers
  the LAPI-bouncer-vs-AppSec distinction (same container, two
  independent components), the three operating scenarios
  post-v1.3.2 hotfix (AppSec off with fail-open absorbing, enable
  properly via `/setup-appsec.sh`, disable entirely via mode =
  `disabled`), and a decision guide for the `appsec.fail_open`
  fail-policy setting.
- **Troubleshooting: new entry** for the `appsec_unavailable`
  notification firing repeatedly — how to distinguish a sidecar up
  with zero collections (404 → unhealthy) from a sidecar actively
  rejecting probes (405 → healthy), and how to silence the
  notification permanently via Scenario C.
- **Release notes: [v1.3.3](docs/release-notes/v1.3.3.md)**.

### Changed

- `docs/features/waf.md` gains a banner at the top steering
  readers looking for setup / fail-policy content to the new
  AppSec page. WAF page stays focused on rules, exclusions,
  paranoia, and metrics.
- `docs/features/crowdsec.md` rewrites the one-line AppSec
  reference to name AppSec as an independent layer in the same
  container (not "see WAF").
- `docs/operations/troubleshooting.md` tightens the existing
  "every request 500s with connection refused" entry — summarises
  the three post-v1.3.2 scenarios inline and cross-links the full
  walkthrough on the new feature page.
- `mkdocs.yml` nav adds **Features → AppSec (WAF-inline)** between
  WAF and CrowdSec.

## [1.3.2] - 2026-04-24

Bug-fix release. The panel's Caddy config omitted the
`apps.crowdsec.appsec_fail_open` flag, so a misconfigured or
missing AppSec sidecar (`cscli appsec-configs list` empty on the
out-of-the-box CrowdSec image) would cascade into HTTP 500
responses for **every host on the panel**. v1.3.2 emits the flag,
defaults it to `true`, and gives operators a UI toggle.

See [release notes](docs/release-notes/v1.3.2.md) for the
reproduction, full fix story, and rollback.

### Fixed

- `caddycfg` now emits `appsec_fail_open: true` (or `false`) inside
  the `apps.crowdsec` block whenever `appsec_url` is set. Previously
  absent; the plugin defaulted to fail-closed, so an unreachable
  AppSec endpoint 500'd every request.

### Added

- New setting `appsec.fail_open` (bool, default `true`). Wired
  through `api/settings.go` whitelist and the reconciler's
  `CrowdSecOpts`.
- New notification event `appsec_unavailable` (severity warning).
  Fires on the reachable → unreachable transition of a 5-minute
  background probe of the AppSec URL.
- New UI: **AppSec → Fail policy** card, two-radio chooser
  (fail-open vs fail-closed). Only shown when AppSec mode != disabled.
- New troubleshooting section:
  ["Every request to every host returns 500 with `dial tcp ... :7423: connect: connection refused`"](docs/operations/troubleshooting.md)
  — covers the pre-v1.3.2 symptom, the fail-open default, and the
  `setup-appsec.sh` runbook.

### Not changed

- No migrations. `appsec.fail_open` is a key/value setting; the
  default is read on each reconcile, no DB row required up front.
- No changes to AppSec mode semantics (detect / block / disabled
  continue to mean exactly what they did in v1.3.1).

## [1.3.1] - 2026-04-22

Docs-only patch. No code changes since 1.3.0.

### Added

- Real UI screenshots for the DNS providers Settings page and host
  form dropdown, replacing the 1×1 placeholders shipped with the
  v1.3.0 GA.
- [Release notes](docs/release-notes/v1.3.1.md) describing the
  swap.

## [1.3.0] - 2026-04-21

DNS providers management: Cloudflare + Route 53 with panel-managed
encrypted credentials and a hot-rotation pipeline that inlines creds
into Caddy's admin API without container restart. Consolidates the
work tracked as [1.3.0-alpha] (backend, below) and [1.3.0-beta] (UI,
below) into a single GA. See
[release notes](docs/release-notes/v1.3.0.md) for the pitch,
migration path, and rollback.

### Added

- **Route 53 as a second native DNS-01 provider**. The custom Caddy
  image bundles both `caddy-dns/cloudflare` (unchanged from v1.2)
  and `caddy-dns/route53` (new). `caddy:2.11-builder-alpine` + 
  `caddy:2.11-alpine` base images pinned so upstream minor bumps no
  longer change module ABI on CI rebuilds.
- **`dns_providers` catalogue table (migration 024)** with seeded
  rows for cloudflare + route53, AES-GCM-encrypted credential blobs
  under `ARGOS_MASTER_KEY` (the same master key protecting OIDC
  client secrets, manual-cert private keys, and the VAPID signing
  key).
- **`hosts.tls_dns_provider` column (migration 025)**, default
  `'cloudflare'` so v1.2 rows migrate without behavioural change.
- **`/api/dns-providers` endpoints**: GET list, GET one, PUT with
  `{enabled, credentials}`. Credentials never ship in GET
  responses. PUT honours the `__UNCHANGED__` sentinel on secret
  fields so operators can rotate one credential without retyping
  the others, and triggers a reconcile automatically.
- **Option 2 credentials pipeline**. Decrypted values are streamed
  inline into the Caddy `/load` JSON on every reconcile. No env-var
  indirection, no container restart on rotation.
- **Boot-time `CLOUDFLARE_API_TOKEN` import**. If the env is set
  and the cloudflare DB row has no credentials, first boot encrypts
  the value in and flips the row to enabled. Idempotent; emits
  one INFO log line; the env var keeps working as a fallback for
  one release (removal scheduled for v1.4).
- **Settings → DNS providers UI**: cards grid with per-provider
  enable toggle, credential form, Configured / Not configured
  badges, secret-field rotation with masked placeholder + Edit
  button, "How to get credentials" deep link to each provider's
  docs, and a trust-boundary callout pointing at
  [Persistence docs](docs/operations/persistence.md). Save triggers
  automatic reconcile; Caddy's reconcile error (if any) surfaces
  inline in the card.
- **Host form DNS provider dropdown** under the DNS-01 radio. Auto-
  selects the sole enabled provider, native `<select>` for
  multiples, amber warning + blocked Save when none are enabled,
  "(not enabled)" label + note when editing a host whose saved
  provider was disabled after creation.
- **Docs**:
  [DNS providers feature page](docs/features/dns-providers.md)
  with UI + API flows and a Tier 2 roadmap table;
  [Add a host workflow](docs/workflows/add-host.md) step 3 covers
  the new field; screenshot placeholders registered with the
  capture checklist.
- **Release notes**:
  [v1.3.0](docs/release-notes/v1.3.0.md). Pre-release notes
  [v1.3.0-alpha](docs/release-notes/prereleases/v1.3.0-alpha.md)
  and [v1.3.0-beta](docs/release-notes/prereleases/v1.3.0-beta.md)
  remain in the archive for history.

### Changed

- `caddycfg.HostsToCaddyConfig` grew a `DNSOpts` argument carrying
  the decrypted-credentials map + a legacy-env flag. The
  `dnsProvider` struct moved from a fixed `{name, api_token}` shape
  to a polymorphic `map[string]any` so each provider's credential
  fields serialise directly.
- `reconciler.New` now takes a `*crypto.Cipher` so it can decrypt
  the credentials map once per reconcile.
- Host POST/PUT no longer requires `CLOUDFLARE_API_TOKEN` to be set
  when `tls_challenge='dns'`; the DNS provider gate moved to
  `validateDNSProvider` which checks the `dns_providers` row (with
  a fallback to the legacy env var for cloudflare only).

### Breaking changes

None. Existing hosts keep Cloudflare behaviour unchanged.

### Migration path

v1.2.x → v1.3.0 is drop-in:

```bash
cd argos-edge
git pull
docker compose build
docker compose up -d
```

Migrations 024 and 025 run at startup. The cloudflare token
auto-import fires on first boot. Subsequent reconciles switch from
the `{env.CLOUDFLARE_API_TOKEN}` placeholder to inline DB credentials.

### Roadmap

v1.3.0 ships with Cloudflare + Route 53. Tier 2 providers (Hetzner,
DigitalOcean, Porkbun, Gandi, deSEC, OVH, DuckDNS, acme-dns) land
on demand in v1.3.x patches — each is roughly a Dockerfile
`--with` line plus a catalogue entry. See the
[DNS providers → Roadmap](docs/features/dns-providers.md#roadmap)
section for the tracking table.

## [1.3.0-beta] - 2026-04-21

Pre-release folded into [1.3.0]. See
[archived release notes](docs/release-notes/prereleases/v1.3.0-beta.md).
Covered the UI layer (Settings page + host-form dropdown) on top of
the v1.3.0-alpha backend.

## [1.3.0-alpha] - 2026-04-21

Pre-release folded into [1.3.0]. See
[archived release notes](docs/release-notes/prereleases/v1.3.0-alpha.md).
Covered the backend (migrations 024/025, `/api/dns-providers`
endpoints, Option 2 inline pipeline, Route 53 support,
CLOUDFLARE_API_TOKEN boot import).

## [1.2.0] - 2026-04-21

Docs-only minor release. Closes the DNS-01 manual gap left open
by v1.1 with a supported external workflow (acme.sh + Import)
rather than a native panel-driven integration.

### Added

- **New page: [Manual DNS workflow](docs/tls/manual-dns-workflow.md)**.
  End-to-end guide for issuing a Let's Encrypt certificate against
  a DNS provider that has no native integration in argos-edge,
  using `acme.sh --dns` in manual mode and importing the resulting
  cert + key via the Certificates → Imported flow. Covers
  prerequisites, TXT-record propagation verification via `dig`,
  the double-command flow (issue prints TXTs, renew completes the
  order), renewal cadence every ~60 days, and troubleshooting for
  common failure modes (stale TXT cache, incomplete chain, LE
  rate limits).
- **Cross-references to the workflow**: inline link from
  [Reverse proxy → TLS challenges](docs/features/reverse-proxy.md#tls-challenges)
  next to the DNS-01 / HTTP-01 / TLS-ALPN-01 sections, plus an
  admonition tip at the top of
  [Manual certificates](docs/features/manual-certs.md) pointing
  operators whose DNS provider lacks an API to the new page.
- **Navigation**: new top-level `TLS` section in `mkdocs.yml`
  hosting the workflow page; natural home for future TLS-specific
  documentation.

### Deferred

- **Native panel-driven DNS-01 manual (Feature 1)**. Technical
  analysis is checked in at
  [`docs/internals/dns01-manual-analysis.md`](docs/internals/dns01-manual-analysis.md)
  (not published in the portal). Finding: the acme.sh + Import
  workflow covers the use case at roughly zero cost versus 3-5
  weeks of orchestration code for a native flow that would
  introduce a second ACME client into the stack, a persistent
  order-state machine, and a larger blast radius for
  `ARGOS_MASTER_KEY` loss. The analysis explicitly recommends
  acmez over lego if the feature is ever built. Revisit only on
  concrete operator feedback showing the external workflow is
  painful enough to justify the cost.

### Not changed

No code, no schema, no compose file changes. Standard upgrade is
`git pull`; nothing in the running stack changes.

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
