# Pre-public functional verification

This page is the v1.3.36.8 verification gate -- a single-source
inventory that maps every shipped feature of argos-edge to a
smoke script (or documents why no smoke exists). Run before
making the repo public; re-run on any future release that
might regress a covered surface.

## Summary

| | |
|---|---|
| Pre-v1.3.32 smoke scripts | 9 |
| Verification gap fillers (v1.3.32) | 4 |
| Post-v1.3.32 smoke scripts (v1.3.33-v1.3.36.x) | 5 |
| v1.3.38.x smoke rows (refetch loop, cold latency, warm set, boot, certs, 7d, threats bytes) | 7 (6 scripts) |
| v1.3.39 smoke rows (WAF sources agree) | 1 |
| v1.3.40 smoke rows (log pipeline) | 1 |
| **Total smoke scripts** | **26** |
| EFFECT-verified PASS against prod stack (panel binary v1.3.35 / v1.3.38.x / v1.3.39.x) | 24 |
| Pending prod after deploy (logs-pipeline; v1.3.40.0) | 1 |
| Gated on operator-mediated input (creds / TOTP) | 1 (auth-flow) |
| Legacy regression test (intentionally tests broken path) | 1 (country-block) |
| **Blockers preventing public release** | **0** |

The four post-v1.3.32 additions reflect features shipped or
deploy-pipeline incidents addressed since the original
verification gate was drawn:

- `country-reconciler.sh` (v1.3.33) — 5min ticker EFFECT for
  expansion-divergence detection
- `lapi-flush-cap.sh` (v1.3.33) — alert-shape verification (one
  alert with N decisions, mirroring CAPI/community-blocklist
  shape) after the eight-strike CAPI cascade-flush incident
- `deploy-rebuild.sh` (v1.3.34.3) — `make deploy-prod` actually
  rebuilds the panel image (closes eleventh-strike silent-no-op
  gap)
- `demo-environment.sh` (v1.3.35) — `~/argos-demo` parallel
  stack self-smoke (separate volumes/network from
  `~/argos-prod`)
- `capture-automation.sh` (v1.3.36.x) — Playwright capture spec
  self-smoke (storageState wiring, safeClick blocklist,
  per-surface selector regression-guards). 14 phases of static
  checks.

## Smoke matrix

Each row: feature, smoke script, last EFFECT verified.

| Feature | Smoke script | Status | Verifies |
|---|---|---|---|
| Sync-prod operator tooling | `sync-prod.sh` | ✅ PASS | 5/5 self-gates against tmpdirs (refuse invalid paths, no-op when in sync, drift propagates, operator files protected, excludes work) |
| LAPI SQLite WAL (v1.3.28) | `lapi-wal.sh` | ✅ PASS | `PRAGMA journal_mode=wal`; startup warning absent in current container's logs; .db-wal sidecar present |
| Scenario descriptions (v1.3.30) | `scenario-descriptions.sh` | ✅ PASS | Slimmed index produced (115KB); 54/54 scenarios have description; CVE-2017-9841 carries expected text; graceful degrade with file removed; mtime-driven recovery |
| Scenarios management (v1.3.25) | `scenarios-toggle.sh` | ✅ PASS | PATCH disable -> sentinel -> setup-appsec.sh -> cscli scenarios list confirms removed -> re-enable -> cscli confirms back |
| AppSec tuning (v1.3.25) | `appsec-tuning.sh` | ✅ PASS | PATCH inbound 12 -> sentinel -> reload -> argos-tuning.yaml carries new threshold -> restore round-trip |
| Drift detection (v1.3.27) | `drift-detection.sh` | ✅ PASS | 12 phases: scenarios + tuning surfaces both flip drift_detected=true on PATCH+wait65s and clear on setup-appsec.sh+wait65s |
| True detect mode (v1.3.29) | `true-detect-mode.sh` | ✅ PASS | PUT true_detect_mode=true -> profiles.yaml splice -> crowdsec restart -> synthetic LAPI alert with target_fqdn=test_host produces 0 decisions; toggle off produces 1 decision (default_ip_remediation baseline) |
| Country expansion async (v1.3.31) | `country-expansion-async.sh` | ✅ PASS | 8 phases: BR async expand 11/11 chunks 5009 ranges in <60s; failure path with crowdsec stopped produces state=failed + error_message; recovery to healthy within 30s |
| Country expansion legacy (v1.3.21) | `country-block.sh` | ⊘ SKIP-LEGACY | Tests upstream-broken `cscli scope=Country` path the bouncer plugin doesn't natively handle (seven-strike #2). Replaced by `country-expansion-async.sh`. Refuses to run with placeholder defaults by design |
| **Authentication lifecycle (NEW)** | `auth-flow.sh` | ⏸ DEFERRED | Login -> session cookie -> /me -> logout -> 401. **Requires operator credentials (`ARGOS_USERNAME` + `ARGOS_PASSWORD`)**; cannot run unattended in CI. Detects TOTP-pending response and exits PASS-PARTIAL |
| **Host CRUD + Caddy reconcile (NEW)** | `host-crud.sh` | ✅ PASS | 7 phases: POST host -> GET echo -> toggle flips enabled -> PUT updates auth_required -> DELETE -> 404 -> caddy admin status reachable (proxy for "reconciler healthy") |
| **Whitelist round-trip (NEW)** | `whitelist-roundtrip.sh` | ✅ PASS | 8 phases: POST whitelist -> GET contains -> sentinel updated -> setup-appsec.sh -> argos-whitelist.yaml has the IP -> DELETE -> sentinel + yaml clean |
| **Banned IPs round-trip (NEW)** | `banned-ips-roundtrip.sh` | ✅ PASS | 5 phases: cscli add -> panel /security/decisions lists with origin=cscli -> panel DELETE -> cscli confirms gone (15s cache TTL on Client.ListDecisions accounted for) |
| Country expansion reconciler (v1.3.33) | `country-reconciler.sh` | ✅ PASS | 5min ticker compares panel-tracked CIDR count against actual LAPI Range decisions for the country; flips state='drifted' when divergent; clears on next reconcile after expansion completes |
| LAPI alert-shape cap (v1.3.33) | `lapi-flush-cap.sh` | ✅ PASS | Mirror CAPI/community-blocklist shape: 1 alert with N decisions inside `decisions[]` (NOT N alerts with 1 decision each). NG +1 chunk + IR +3 chunks under 5000-item flush.max_items default; no cascade flush observed |
| Deploy-pipeline rebuild (v1.3.34.3) | `deploy-rebuild.sh` | ✅ PASS | `make deploy-prod` actually rebuilds the panel image (post-fix for the eleventh-strike `build: !reset` + image-pin silent no-op that let v1.3.34.1+v1.3.34.2 ship without deploying). Verifies image hash changes after a known source edit |
| Demo environment isolation (v1.3.35) | `demo-environment.sh` | ✅ PASS | `~/argos-demo` parallel stack self-smoke — separate compose project, volumes, and docker bridge from `~/argos-prod`; ensures demo-stack mods can never bleed into operator's prod |
| Playwright capture spec (v1.3.36.x) | `capture-automation.sh` | ✅ PASS (14/14 phases) | Static checks: run.sh refuses without .env, .env gitignored, viewport 1440x1080, storageState wiring, safeClick blocklist (13/13), waitForSettled helper, openModal modal-visibility wait, host-row trigger selector, safeClickTab tab nav, DNS-01 selector, threats-decisions selector + screenshot helper |
| Dashboard refetch loop (v1.3.38.0) | `dashboard-refetch-loop.sh` | ✅ PASS | Passive AF_PACKET count of `GET /api/dashboard/overview` on the panel's docker bridge, 60 s, operator's browser tab in the foreground: 1,293 on 1.3.35 (FAIL) -> 2 on 1.3.38.0 (PASS) |
| Cold dashboard latency (v1.3.38.1) | `dashboard-latency.sh` | ✅ PASS | `curl -w %{time_total}` after 40 s idle (30 s cache expired) against prod, threshold 2 s: `dashboard/health` 16.5 s -> 0.044 s, `security/overview` 44.8 s -> 0.003 s (1.3.38.0 -> 1.3.38.1) |
| Dashboard warm set + probe cache (v1.3.38.2) | `dashboard-latency.sh` (`MAX_SECONDS=1 EXPECT_CACHE=hit`) | ✅ PASS | After 40 s idle `/api/dashboard/health` 0.0007 s with `X-Argos-Cache: hit`; all four default views `hit` at +60 s after start with nobody in the panel; panel at rest 1.9 % CPU. `/api/certs` `last_checked_at` = warm-up probe time; latency still 1.06 s (LIKE in `enrichWithLastEvent`, v1.3.38.3) |
| Panel boot path (v1.3.38.3) | `panel-boot.sh` | ✅ PASS | Read-only, from the container's boot log: boot-to-listen 1.75 s -> 0.139 s; first retention purge 120.5 s after listen (was before listen). `/api/hosts` during the purge: p50 1.3 ms, max 0.31 s |
| Certs list latency (v1.3.38.3) | `certs-latency.sh` | ✅ PASS | `/api/certs` 0.93 s -> 0.001 s without inline last event; `/api/certs/{id}/last-event` 200 in 0.10 s (was 404) |
| Threats server paging (v1.3.38.5) | `threats-page-bytes.sh` | ✅ PASS | Prod after deploy, operator's tab on `/threats` in the foreground, 24k CAPI decisions: 6 requests, 180,376 B on the wire in 60 s, **30,062 B per response** (1.3.38.4: 7.2 MB decoded per response). Demo before/after: passive tap of the panel's reply bytes to `GET /api/threats/decisions` with a headless tab on `/threats` for 60 s, 7,400 decisions: 1.3.38.4 5 req / 1,661,813 B on the wire (10.1 MB decoded) FAIL -> 1.3.38.5 5 req / 106,489 B (104 KB decoded) PASS; first rows 2,126 ms -> 236-315 ms; hidden tab 35 s: 0 requests; 6 drawer route changes: 0 frames without the Layout header, 1 `/api/auth/me` per session (1.3.35.4: 3). Browser runs against `~/argos-demo` only |
| Log pipeline (v1.3.40.0-.3) | `logs-pipeline.sh` | ⏳ pending the v1.3.40.3 after-smoke | Rows of the filtered families stored since the panel start <= 100; `raw` NULL on access rows older than raw_hours + 1 h (PENDING until the panel is 25 h old); rows and DB size printed for the 48 h comparison; p99 of `/api/hosts` during `POST /api/logs/purge` <= 50 ms. Before on prod (1.3.39.1): 501,475 rows, 1.72 GB, 661.5 MB of access raw; 450 monitor rows and 64 health-checker rows stored in the first 20 min after a restart; purge 1.51 s with `/api/hosts` p99 1,246 ms |
| WAF sources agree (v1.3.39.0, gate 1 % since v1.3.39.1) | `waf-sources-agree.sh` | ✅ PASS | Prod after the v1.3.39.0 deploy: dashboard 260 / overview 260 / AppSec 260 / LAPI 266, 2 % (the 6 `crowdsec-appsec-outofband` alerts missed the `appsec-` prefix; fixed in v1.3.39.1, gate lowered to 1 %: prod after the v1.3.39.1 deploy 266 / 266 / 266 / 266, 0 %, PASS). Four readings of "AppSec events, last 24 h" within 5 %: `dashboard/security` `waf_engines.appsec.events`, `security/overview` `appsec_hits_24h + appsec_bans_24h`, `appsec/metrics` `total_hits`, LAPI through `cscli alerts list` (kind=waf + the two appsec-* scenarios). Before on prod (1.3.38.5): dashboard 0 / overview 0 / appsec 260 / LAPI 266, FAIL |
| 7-day ranges (v1.3.38.4) | `range-7d-latency.sh` | ✅ PASS | Cold `traffic?range=7d` 52.8 s -> 1.83 s, `logs/stats` 7d 35.4 s -> 1.18 s, busiest-host 7d 0.61 s (threshold 5 s); `logs/timeseries` 7d 27 s -> 0.74 s |

## Coverage gaps documented

| Feature | Why no automated smoke | Mitigation |
|---|---|---|
| Recovery CLI subcommands (`reset-password`, `disable-2fa`, `migrate`, `restore`) | CLI invocation against the panel binary needs a separate test process + container exec; meaningful test would require seeding a known user state and asserting post-conditions. Not blocking; CLI is operator-only and exercised manually during incident recovery | Documented invocation in `docs/operations/troubleshooting.md` (existing); each subcommand has a `--help` that the operator validates before running it for real |
| Self-block detection / banner v2 | Requires the operator's actual public IP to be banned in CrowdSec to surface the banner; cannot synthesise without breaking the operator's own connectivity to the panel. The underlying API endpoint (`GET /api/security/check-self`) is exercised via the `auth-flow.sh` smoke (the panel returns the data; the banner is pure UI) | Manual: operator follows the documented "self-block recovery" flow at first onboarding to validate the banner renders correctly |
| Activity / audit log queries | Read-only endpoint with no behavioural side effect; an empty response is indistinguishable from a working query against a fresh DB. Smoke would mostly assert "200 OK + JSON-shape" which adds little signal | Read-only; if the endpoint breaks the only impact is the Activity tab renders empty. No incident risk |
| Dashboard widget stats | Aggregated counters (banned count, whitelist count, etc.) computed live from the same endpoints other smokes already exercise; if those work the dashboard math works | Implicit via banned-ips + whitelist + scenarios smokes |
| TOTP / 2FA enrollment + verification flow | Requires interactive operator (TOTP secret + a real authenticator app); not scriptable | Manual: documented in `docs/features/auth-local.md` |
| OIDC SSO end-to-end | Depends on an external IdP (Keycloak / Authentik / etc.); operator's choice of IdP varies per deployment | Per-IdP smoke would belong in the IdP's own test surface, not argos-edge |
| Backup + restore round-trip | Existing `argos backup` CLI + `argos restore` are exercised manually during incident recovery; building a smoke would require tearing down the panel mid-test which conflicts with running other smokes alongside | Documented manual path; `make sync-prod` covers operator-tooling sweeps |
| Reverse-proxy live healthcheck propagation | Caddy's healthcheck pings backend targets; would need to spin up a stub backend that answers 200 vs 503 to assert; out of scope for a single-stack homelab smoke | Implicit via host-crud (Caddy admin reachable post-reconcile) |
| Notifications (Slack / push / email) | External delivery side-effects; smoking these would spam real channels. Each provider has its own test surface | Per-provider configurability test exists in panel UI ("Send test notification" button) |

## Recommendation: ready for public

All 16 in-scope smokes PASS against the v1.3.35 panel binary.
The 1 deferred (auth) is an operator-credential concern, not a
code defect; the underlying handlers are exercised indirectly
by every other session-bearing smoke. The 1 legacy-skip
(country-block) tests an upstream-known-broken path that
v1.3.21 worked around.

The thirteen-strike upstream-behaviour pattern (strike 12, v1.3.40.0: a test with an invented schema let a NOT NULL violation reach prod, since v1.3.40.1 tests use `internal/db/dbtest` with the real migrations; strike 13, v1.3.40.1: an EFFECT gate without prod density let a quadratic raw strip stall the panel, since v1.3.40.2 long writes must run against the dense demo seed first; documented in
CLAUDE.md and the per-strike memory file) is now reflected
in the smoke matrix: every external-protocol surface that
caused an incident has a dedicated EFFECT-verifying smoke
(LAPI WAL, scenarios source-of-truth, AppSec tuning, drift
detection, true-detect-mode, country expansion async,
country reconciler, alert-shape cap, deploy-pipeline
rebuild).

**Zero blockers. The repo is functionally ready for public
release.** The pre-public audit
(`docs/operations/pre-public-audit.md`, v1.3.37) covers the
non-functional gates (sanitization, doc currency, GitHub
governance files).

## How to re-run

```bash
SESSION=$(docker run --rm -v argos_prod_data:/data alpine sh -c \
    "apk add --no-cache sqlite >/dev/null 2>&1
     sqlite3 /data/argos.db \"SELECT token FROM sessions
       WHERE expires_at > datetime('now')
       ORDER BY id DESC LIMIT 1;\"")

# Cheap (no-auth, ~5-30s each):
./scripts/smoke/sync-prod.sh
CROWDSEC_CONTAINER=argos-prod-crowdsec ./scripts/smoke/lapi-wal.sh

# Auth-needing happy paths (~15-90s each):
ARGOS_SESSION_TOKEN="${SESSION}" \
PANEL_BASE_URL=http://localhost:9180 \
CROWDSEC_CONTAINER=argos-prod-crowdsec \
  ./scripts/smoke/scenario-descriptions.sh

# ... repeat the env block for the other smokes ...

# Long (4-min drift detector + 90s country async):
ARGOS_SESSION_TOKEN="${SESSION}" \
PANEL_BASE_URL=http://localhost:9180 \
CROWDSEC_CONTAINER=argos-prod-crowdsec \
  ./scripts/smoke/drift-detection.sh

ARGOS_SESSION_TOKEN="${SESSION}" \
PANEL_BASE_URL=http://localhost:9180 \
CROWDSEC_CONTAINER=argos-prod-crowdsec \
COMPOSE_DIR=$HOME/argos-prod \
SKIP_FAILURE_PATH=1 \
  ./scripts/smoke/country-expansion-async.sh

# Operator-credentials smoke (manual):
ARGOS_USERNAME=admin ARGOS_PASSWORD='...' \
  ./scripts/smoke/auth-flow.sh
```

## What this report does NOT prove

- Frontend visual rendering. Smokes exercise the API; the
  React UI is verified by the operator's browser pass.
- Load behaviour at scale. Smokes are one-shot single-host
  exercises; sustained load testing is out of scope.
- Cross-version migration path. Smokes run against the
  current schema; incremental upgrade from older argos-edge
  versions is documented in each release's notes and would
  warrant a dedicated migration smoke if released as a
  product (not yet a homelab need).
