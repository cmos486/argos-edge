# UX + perceived-performance review (PHASE 0)

Read-only review of the panel as deployed on the operator's prod
LXC. Goal: make what already exists coherent, fast to open and
easy to find. No features. This page is the PHASE 0 deliverable;
nothing has been changed in code, compose files or running
stacks. PHASE 1 scope is proposed at the end and waits for
operator approval.

**Review date**: 2026-09-25
**Panel binary measured**: `1.3.35` (commit `d6a32b3`), running
in `argos-prod-panel`
**Repo HEAD**: `66e414c` (v1.3.37)
**Method**: LXC inventory, source map (frontend + backend), HTTP
GET timing against the live prod panel, `EXPLAIN QUERY PLAN` and
single-query timing against a `sqlite3 .backup` copy of the prod
DB (copy deleted afterwards), headless-browser paint timing per
route.

**Status**: sections 0-8 are the PHASE 0 record as measured on
`1.3.35` and are kept as written. Section 9 is the live status
after v1.3.38.0-v1.3.38.5 (2026-09-26): what closed, with the
before/after measured on prod, what is open and when.

## 0. Executive summary

| Finding | Evidence | Fix class |
|---|---|---|
| **Dashboard refetches `/api/dashboard/overview` in a tight loop for as long as the tab is open** | headless Chromium counted 2,896 API calls in 240 s on `/`; `Dashboard.tsx:78` passes a new `onLoaded` arrow on every render and the effect at `:153` depends on it, so fetch -> `setLastUpdated` -> re-render -> new callback -> fetch | frontend, one-line fix (P0) |
| Threats page renders all 24,060 CAPI decisions in the DOM, never settles | headless Chromium > 120 s to settle; 7.2 MB per 15 s poll and per keystroke | backend pagination + frontend (P0) |
| Dashboard opens in 21-37 s after 30 s idle | `/api/dashboard/health` 21-25 s cold; blocking 30 s cache, no warm-up | backend, no schema |
| Any "7d" range freezes the whole panel for ~2 min | `dashboard/traffic?range=7d` 119 s, `logs/stats` 7d 120 s | backend, no schema (rollups would need schema) |
| One slow read blocks every other request and the ingestor | `SetMaxOpenConns(1)`; `/api/hosts` p50 1 ms, max 24.7 s while health recomputed | backend, documented architecture decision (needs operator OK) |
| Security overview 30 s cold | 19 hosts x 3 queries, one of them scans every row of the host | backend, no schema |
| Dashboard "Security" section is fed by a dead source | `waf_audit` has 0 rows; `waf-audit.log` is 0 bytes since April; AppSec page reads LAPI alerts instead | product coherence |
| Search is per-page, per-keystroke, unshared | no debounce anywhere; Threats re-downloads 7.2 MB per keystroke; Logs ignores `q`/`status` from incoming links | frontend |
| Four time-range pickers, three "decisions" tables, two "blocked" definitions | see section 4 | frontend + naming |

## 1. Environment inventory (LXC)

Host: 2 vCPU, 2048 MB RAM (swap 512 MB, 169 MB in use), root
disk 28 GB at **91 % used, 2.5 GB free**. Load average ~2.5 on 2
cores at rest. The panel is limited to 512 MB, Caddy 256 MB,
CrowdSec 256 MB (CrowdSec sits at 206-228 MB of its 256 MB cap).

Directories:

| Dir | Role | Notes |
|---|---|---|
| `~/argos-edge` | git checkout, edits, smoke, capture | HEAD v1.3.37 |
| `~/argos-prod` | operational compose stack | older checkout (v1.3.36.8 tree + `docker-compose.override.yml`); `crowdsec/` and `Caddyfile` identical to `~/argos-edge` (no bind-mount drift) |
| `~/argos-demo` | isolated demo compose | **stack is down**; only volumes `argos_demo_*` remain; not started during this review (RAM headroom) |

Running containers (all belong to the prod stack):

| Container | Image | Compose project label | Network |
|---|---|---|---|
| `argos-prod-panel` | `argos-prod-argos:1.3.35` | `argos-edge` | `argos_prod_net` |
| `argos-prod-caddy` | `argos-caddy:v1.3-alpha` | `argos-edge` | `argos_prod_net` |
| `argos-prod-crowdsec` | `crowdsecurity/crowdsec:latest` | `argos-edge` | `argos_prod_net` |
| `argos-prod-crowdsec-init` | (exited 0, 5 months) | `argos-edge` | none |
| `argos-crowdsec-init` | (exited 0, 5 months) | **`argos-prod`**, working dir `~/argos-edge` | none |

Volumes in use by prod: `argos_prod_*` (9). Orphans: `argos_*`
without prefix (7: `argos_caddy_*`, `argos_crowdsec_*`,
`argos_panel_*`, `argos_shared_setup`) and network `argos_net`.
Demo: `argos_demo_*` (9), no network, no containers.

### 1.1 Anomalies (STOP+REPORT before any state-changing step)

1. **Compose project name is inverted with respect to the working
   agreement.** `docker-compose.yml` declares `name: argos-edge`,
   and the prod override does not rename the project, so the
   live prod stack is compose project **`argos-edge`** (config
   files under `~/argos-prod`). The project named `argos-prod`
   is a dead leftover: one exited `argos-crowdsec-init` started
   from `~/argos-edge/docker-compose.yml`. Consequence: a
   `docker compose -p argos-prod ...` command targets the orphan,
   and `-p argos-edge` targets prod. Every operator note and
   script that assumes `-p argos-prod` is wrong today. Nothing
   was run against either project during this review.
2. **Image pin vs running image.** The prod override pins
   `image: argos-prod-argos:1.3.35.4`, the running container is
   `argos-prod-argos:1.3.35` (binary reports `1.3.35`, built
   2026-04-27). Images `1.3.35.2`, `1.3.35.3`, `1.3.35.4` exist
   locally but were never rolled into the container (container
   is 12 days old, i.e. restarted with the old image on the last
   host reboot). v1.3.35.2-.4 are demo/tooling patches, so no
   prod behaviour is missing, but this is the strike-11 shape:
   the compose file says one thing, `docker ps` another. The
   `deploy-rebuild.sh` smoke would have caught it.
3. **Disk at 91 %.** A `.backup` copy of the 1.7 GB DB took the
   root FS to 97 %; the copy was removed. Nightly backups are
   ~128 MB each (14 kept, ~1.75 GB). Any PHASE 1 work that needs
   a DB copy or the demo stack must budget disk first.
4. **RAM headroom** is ~1.4 GB "available" but almost all of it
   is page cache holding the DB. Starting the demo stack
   (3 containers, ~400 MB) evicts that cache and slows prod
   reads; the cold numbers below would get worse, not better.

Orphans (1) and the pin mismatch (2) are operator decisions;
nothing here requires them to be fixed before PHASE 1, but (1)
must be settled before any smoke that uses `docker compose -p`.

## 2. Navigation map and frictions

### 2.1 Current map

Twelve flat entries in a hamburger drawer at every viewport
(`frontend/src/components/Layout.tsx:21-34`): Dashboard, Hosts,
Target Groups, Security, Threats, AppSec, Notifications,
Certificates, Logs, Backup, System, Settings. Header pills link
to `/system` (version, LAN mode) and `/appsec`.

Pages reachable only through in-page links: `/hosts/:id/rules`,
`/hosts/:id/security`, `/security/hosts` (Security overview),
`/target-groups/:id`. Tabbed pages keep the active tab in
component state only (Security 5 tabs, Notifications 4,
Backup 3, Certificates 2): a reload or a shared link always
lands on the first tab.

Global behaviours that shape every navigation:

- `ProtectedRoute` re-fetches `/api/auth/me` and blanks the page
  to a "loading..." screen on **every route change**
  (`ProtectedRoute.tsx:22-48`, remounted per route in
  `App.tsx:88-94`).
- `SelfBlockBanner` polls `/api/security/check-self` every 60 s
  on every page; each poll is one LAPI round-trip per session IP
  (0.13-0.19 s measured).
- `Layout` polls `/api/appsec/status` every 30 s (a live HTTP
  probe to `crowdsec:7423`).
- No URL state anywhere (`useSearchParams` unused), no
  `document.title`, no breadcrumbs except Rules.

### 2.2 "Where does each thing live"

| Concept | Page(s) where it appears | Search / filter that covers it | Duplicate / gap |
|---|---|---|---|
| Host | Hosts; Security overview (`/security/hosts`); Dashboard traffic host select; Notifications rules host picker | none in Hosts (no search, no sort); host select only in Dashboard traffic | Logs has no host selector, only `?host_id=` from links |
| Target group / backend health | Target Groups; TG detail (30 s poll); Dashboard health card | none | TG list has no health badge; detail "Used by hosts: N" not linked |
| CrowdSec decision (ban) | Security > Banned IPs; **Threats** (same LAPI list, different columns/actions); SelfBlockBanner; Dashboard "Active bans" card | Banned IPs: `q` + scope + origin, server-paged 100; Threats: `search` + origin + type, **no pagination, 7.2 MB response** | Two tables for one entity. Threats "remove" button reads **"whitelist"** but only deletes the decision; Banned IPs says "Unban". Threats search is case-sensitive, Banned IPs is not |
| Country ban expansion | **Settings** (bottom); Dashboard "Country expansions" card | none | Not under Security or Threats. `/api/security/countries` returns every CIDR inline (770 KB) |
| Whitelist | Security > Whitelist; SelfBlockBanner "Whitelist permanently" | none | fine |
| WAF / AppSec activity | Dashboard "Security" section (source `waf_audit`, **0 rows**); Security overview "Blocked 24h" (`waf_audit`, always 0); Logs preset "WAF blocks" (`waf_audit`, empty); **AppSec page** (LAPI alerts, 172 hits in 24 h); Threats (decisions) | AppSec: window 1h/6h/12h/24h; Dashboard: range 1h/6h/24h/7d | Same question, five answers, four of them empty |
| WAF policy per host | Hosts > shield icon > HostSecurity; Security overview > Configure | none | Save on HostSecurity navigates to `/security` (global tabs), not back where you came from |
| Scenarios / tuning / drift | Security > Scenarios, AppSec tabs; drift polled 10 s | none (no search over ~100 scenarios) | AppSec page (`/appsec`) vs Security > AppSec tab share a name and differ in content |
| Access log entry | Logs; Dashboard cards link into Logs | Logs: q, source, status, method, path(+regex), range 15m-7d, `host_id` by URL only | Incoming `q`, `status`, `path` params are **ignored** (`Logs.tsx:46-54` reads only `host_id`, `source`); `waf_audit` missing from the source select while links send it |
| Audit (panel actions) | Security > Activity; Logs `source=audit`; Dashboard "Audit events 24h" | Activity: `q` after-fetch substring on a `limit*5` window (inconsistent totals) | 3 audit rows in prod; two views of the same rows |
| Notification delivery | Notifications > History (cap 300, no pagination) | range 24h/7d/30d as hour counts, status, event_type per-keystroke | `recent-alerts` endpoint exists and is unused |
| Certificate | Certificates > Active (TLS probe per host, 1.1-3 s each load); Dashboard overview "Certs <=14d" and health card (their own probe sets) | none | three independent probe passes of the same 19 hosts |
| Backup | Backup; Dashboard "last backup" | none | fine |
| GeoIP / 2FA / SSO / system health | System | none | fine |
| Logs retention, session timeouts, ACME, DNS, **country bans** | Settings | none | country bans mis-filed |

### 2.3 Concrete frictions ("I want X, I have to go A -> B -> C")

1. **"Is this IP banned, why, and what did it do?"** Threats
   (search, case-sensitive) or Security > Banned IPs (search,
   case-insensitive) for the decision; then Logs, paste the IP
   into `q` (which LIKEs the 1.4 KB `raw` column of every row in
   range) for its requests; Dashboard "top attacking IPs" links
   to `/logs?q=<ip>` but Logs drops `q`, so you land on the
   unfiltered log. Three pages, three inputs, one broken link.
2. **"Turn the WAF to block for host X."** Hosts -> shield icon
   -> HostSecurity -> Save -> you are dropped on `/security`
   Banned IPs tab. Or Security -> "Hosts" link -> overview ->
   Configure -> Save -> same drop.
3. **"Ban a country."** Settings (last section of the longest
   page). Progress polls 1 s for up to 10 min. Not discoverable
   from Security or Threats.
4. **"Is the WAF doing anything?"** Dashboard says "No WAF events
   in range" (dead source). Security overview says "Blocked 24h:
   0". AppSec page says 172 blocked. Threats shows bans. The
   operator has to know which one is real.
5. **"What did the panel change yesterday?"** Security > Activity
   tab (not a top-level entry), or Logs with source=audit; the
   Dashboard card counts them but does not link.
6. **"Open the panel and see if things are fine."** Dashboard
   after >30 s idle: 5 requests, one of which (`health`) blocks
   21-25 s, during which every other request in the panel and
   the log ingestor queue behind it (section 3.3). Each section
   shows "loading..." until its own call returns; there is no
   cached last-known state.
7. **"Share a view with future me."** No URL carries tab, range,
   filter or search state; a bookmark or a reload always resets
   to defaults.

## 3. Load time per page (measured against prod)

### 3.1 API endpoint timing

Method: `curl` with the operator session cookie from the LXC
itself (no network hop). "cold" = first call after >30 s idle
(every 30 s cache expired) with the DB mostly in the OS page
cache; "first" = the very first call of the session while the
DB copy was being made (cold disk + contention), shown to bound
the worst case an operator sees after a quiet night. "warm" =
immediate repeat.

| Endpoint (page) | first | cold | warm | bytes | Root cause |
|---|---|---|---|---|---|
| `GET /api/logs/stats?from=<7d>` (Logs, 7d) | - | **119.8 s** | 0.01 s | 821 | 6 aggregate queries each visiting every row in range (9-14 s each on the copy: COUNT+AVG 9.7 s, p95 sort 14.5 s, top paths 13.3 s), serialised on the single connection |
| `GET /api/dashboard/traffic?range=7d` | - | **119.5 s** | 0.001 s | 29 KB | 5 queries, two fetch every row (481k rows, 11.0 s and 9.3 s on the copy) to bucket in Go; GROUP BY on host_domain,path 12.6 s |
| `GET /api/logs/stats` (no `from`) | 117 s | - | 0.001 s | 821 | same over all 502k rows |
| `GET /api/dashboard/health` | 37 s | **21-25 s** | 0.001 s | 5.5 KB | `RecentErrors`: OR across two sources with no time bound -> multi-index OR over all 480k access rows + temp sort (12.6 s alone on the copy); plus 19 parallel TLS probes and a live Caddy admin call |
| `GET /api/security/overview` | 33.7 s | **30.3 s** | 0.001 s | 3.7 KB | N+1: per host `MAX(timestamp) ... WHERE source='waf_audit' AND host_id=?` walks every row of that host because no `waf_audit` row exists (9.4 s for the busiest host with 271k rows); 19 hosts x 3 queries |
| `GET /api/logs/timeseries` (no `from`) | 27 s | - | 0.006 s | **1.16 MB** | every row fetched, bucketed in Go |
| `GET /api/dashboard/traffic?range=24h` | 16.0 s | 0.88 s | 0.001 s | 17 KB | same shape, 70k rows |
| `GET /api/dashboard/overview` | 7.5 s | 0.33 s | 0.001 s | 213 | 24 h aggregate + 19 TLS probes + backup list |
| `GET /api/certs` | 3.1 s | **1.1-3.0 s every call** | same | 4 KB | no cache; sequential TLS probe per host + `LOWER(message) LIKE '%domain%'` over all 21k `caddy_error` rows (0.9 s per host when no match) |
| `GET /api/dashboard/security?range=7d` | - | 1.24 s | 0.001 s | 10 KB | 7 queries over `waf_audit` (empty) + 403/429 scans |
| `GET /api/logs/stats?from=<1h>` | - | 1.0 s | 0.001 s | 774 | 6 queries over 1 h of rows |
| `GET /api/logs/stats?from=<24h>` | - | 0.83 s | 0.001 s | 801 | idem 24 h (COUNT+AVG alone 1.9 s on the copy) |
| `GET /api/appsec/metrics?window=24h` | 1.2 s | 0.10 s | 0.001 s | 5 KB | LAPI `/v1/alerts` (500 cap) + Go aggregation, 30 s cache |
| `GET /api/logs?from=<24h>&remote_ip=x` | - | 0.23-0.25 s | same | 48 | `remote_ip LIKE '%x%'` over 24 h of rows, no index |
| `GET /api/threats/decisions` | - | 0.15 s | 0.14 s | **7.2 MB** | full decision list (country-expansion Range decisions) with geo enrichment, no pagination; re-fetched on every keystroke and every 15 s |
| `GET /api/security/check-self` | - | 0.13-0.19 s | same | 251 | one LAPI GET per session IP, polled every 60 s on every page |
| `GET /api/security/countries` | - | 0.02 s | same | **770 KB** | every CIDR of every expansion inline |
| `GET /api/caddy/status` | - | 0.1-0.16 s | same | 58 | live admin API call |
| `GET /api/hosts`, `/target-groups`, `/settings`, `/backups`, `/security/decisions`, `/security/audit-log`, `/threats/stats` | - | 1-7 ms | - | - | fine |

Ranges for the dashboard on the same cold cache: traffic 1h
0.05 s, 6h 0.22 s, 24h 0.88 s, 7d 119.5 s; security 1h 0.004 s,
6h 0.01 s, 24h 0.02 s, 7d 1.24 s.

### 3.2 Per-page composition

From the frontend map (calls on mount, poll interval) combined
with the timings above. "Cold open" is the sum an operator waits
for the slowest card after >30 s idle.

| Page | Calls on mount | Poll | Cold open bound | Notes |
|---|---|---|---|---|
| Dashboard `/` | `auth/me`, then `overview`, `hosts`, `traffic`, `security`, `dashboard-stats`, `health` (parallel) + layout `system/health`, `system/version`, `appsec/status`, `check-self` | 30 s all five | **21-25 s** (health), 37 s with cold disk | `overview` effect depends on an inline `onLoaded` callback (`Dashboard.tsx:78,153`): every completed fetch triggers a parent re-render, a new callback identity and a new fetch. In the browser this is a continuous loop at network latency (~12 req/s measured, section 8), not a one-off double fetch. The 30 s cache makes each hit cheap server-side, but the browser tab never goes idle and every cache expiry is hit immediately. Per-section "loading..." only; no last-known data |
| Security overview `/security/hosts` | `security/overview` | 30 s | **30 s** | renders nothing until data |
| Logs `/logs` (default 1h) | `logs`, `logs/stats` (parallel), `logs/presets` | none (SSE opt-in) | ~1 s | selecting **7d** = 120 s and blocks the panel; every keystroke re-runs both |
| Certificates | `certs` | none | 1.1-3 s every visit | no cache |
| Threats | `status`, `scenarios`, `stats`, `decisions` | 15 s, all four | 0.3 s but 7.2 MB per cycle | per keystroke |
| AppSec | `appsec/status`, `appsec/metrics` | 30 s | 0.1-1.2 s | fine after first |
| Security `/security` | tab fetch + `drift` | drift 10 s | <10 ms | Banned IPs per keystroke |
| Hosts, Target groups, Notifications, Backup, System, Settings | 1-7 small calls | System 10 s | <50 ms | Settings fires 7 requests; Backup settings has its own fetch clone |

### 3.3 The single-connection effect (EFFECT verified)

`internal/db/db.go:61` sets `SetMaxOpenConns(1)`; `docs/
architecture/storage.md` documents it as the single-writer
choice. In practice it also serialises **every read**: WAL's
concurrent readers are never used.

Probe: 40 x `GET /api/hosts` every 250 ms while
`GET /api/dashboard/health` recomputed cold.

| | value |
|---|---|
| `/api/hosts` p50 | 1.3 ms |
| `/api/hosts` max | **24.7 s** (the request that queued behind the health recompute) |
| `/api/dashboard/health` | 24.7 s |

The same applies to the log ingestor flush (every 2 s), session
touch, drift detector writes and the notification worker: all
wait behind any of the slow reads above. A 7d range selection
therefore stalls ingestion for two minutes.

### 3.4 Database shape (copy of prod)

| Metric | Value |
|---|---|
| File size | 1.72 GB (419,943 pages x 4 KB), freelist 72 MB |
| `log_entries` | 502,297 rows, **1,267 MB** table + 303 MB across 6 indexes |
| Everything else | < 1 MB combined (`country_ban_expansions` 0.7 MB) |
| Rows/day | 68-79k (access 480,806; error 21,488; audit 3; **waf_audit 0**) |
| Avg `raw` per access row | 1,457 bytes (+99 B user_agent, 37 B path) |
| Effective retention | ~7 days: `logs.max_entries=500000` is hit long before `logs.retention_days=30` |
| `caddy_error` rows | 21,657, of which **20,222 (93 %)** are `health_checker.active` noise |
| `sqlite_stat1` | absent (no `ANALYZE` ever run; planner works without statistics) |
| `sessions` | 67 rows, never purged |
| `notification_deliveries` | 0 rows |

Why every "visit each row" query costs ~10 s: rows average
~2.5 KB on disk because of `raw`, so reading `timestamp,status`
for 480k rows means touching 1.2 GB of pages. A covering-index
count over the same window takes 0.027 s.

### 3.5 Query plans and as-shipped vs proposed shapes (copy of prod)

| Query | As shipped | Proposed shape | Proposed |
|---|---|---|---|
| Dashboard health `RecentErrors` | 12.6 s (MULTI-INDEX OR, no time bound, temp sort) | bound to 24 h: 1.9 s; two indexed sub-selects `UNION ALL ... LIMIT 10`: **0.024 s** | no schema |
| Security overview per-host (busiest host) | `MAX(timestamp)` 9.4 s + count 1.5 s, x19 hosts | one `GROUP BY host_id` over `source='waf_audit' AND timestamp>=24h`: **0.003 s** | no schema |
| Traffic 7d timeseries | 11.0 s + 9.3 s row fetches | same via `substr(timestamp,1,13)` GROUP BY: 10.6 s (still visits rows). Real fix: covering-index COUNTs per status class per bucket, or hourly rollup table | rollup = schema |
| Logs stats 7d | 9.7 + 14.5 + 13.3 s (+3 more) | 24 h via same queries: 1.9 s. Real fix as above; p95 needs a sample or a rollup | rollup = schema |
| Logs `q` free text | LIKE over `raw` for every row in range: 24 h 1.9 s, 7d 11.7 s | keep, but never on `raw` by default; `remote_ip` exact match on its own index | index = schema (additive) |
| Certs last event | `LOWER(message) LIKE` over all `caddy_error` rows, 0.9 s per host | bound to the last 30 days or match on `host_domain` column | no schema |

## 4. Search and filter inventory, and a unified model

### 4.1 Inventory

| Page | Input | Param / field | Side | Debounce | In URL | Notes |
|---|---|---|---|---|---|---|
| Logs | search | `q` -> `path/user_agent/message/raw LIKE` | server | no | no | incoming `q` ignored |
| Logs | source select | `source` (no `waf_audit` option) | server | - | read once | |
| Logs | status / method / path (+re) | `status`, `method`, `path` | server | no | no | |
| Logs | range 15m/1h/6h/24h/7d | `from` ISO | server | - | no | |
| Logs | host | `host_id` | server | - | read once | no UI control |
| Dashboard traffic | range 1h/6h/24h/7d, host select | `range`, `host_id` | server | - | no | |
| Dashboard security | range 1h/6h/24h/7d (separate state) | `range` | server | - | no | two independent ranges on one page |
| AppSec | window 1h/6h/12h/24h | `window` | server | - | no | |
| Notifications history | range 24/168/720 h, status, event_type | `from/to`, `status`, `event_type` | server | no | no | cap 300 |
| Security > Banned IPs | search, scope, origin | `q`, `scope`, `origin` | server (in-memory list) | no | no | paged 100 |
| Security > Activity | search | `q` after-fetch | server | no | no | window `limit*5` |
| Threats | search, origin, type | `search`, `origin`, `type` | server (in-memory list) | no | no | no pagination, case-sensitive |
| Hosts, TGs, Certificates, Scenarios, Whitelist, Backups, Channels, Rules | none | | | | | |

Backend naming for the same things: `q` (logs, security) vs
`search` (threats); `total` (security decisions) vs `total_count`
(logs) vs nothing (deliveries); `range` (dashboard) vs `window`
(appsec) vs `from`/`to` (logs, deliveries); `limit` defaults
100/100/200/20/5 with maxes 1000/1000/1000/200/50; removal
outcomes `unbanned`/`deleted`/`removed`.

UI naming: "Banned IPs" and "Unban" (Security) vs "Active
decisions" and a **"whitelist"** button that removes a ban
(Threats) vs "Active bans" (Dashboard). "Blocked" means
`status IN (403,429)` on the Dashboard overview, `status=403` in
the security chart, `waf_audit CRITICAL/ERROR` rows in Security
overview, and `alert with decision or block mode` on the AppSec
page. "Alerts" means CrowdSec alerts (AppSec), notification
deliveries (`recent-alerts`), and WAF counts
(`alerts_critical_24h`, which is numerically the same as
`blocked_24h_total`).

### 4.2 Proposed unified model

One `FilterBar` component and one query vocabulary, used by
every page that lists or aggregates time-bound data:

| Field | Values | Applies to |
|---|---|---|
| `range` | `15m`, `1h`, `6h`, `24h`, `7d` (server converts to `from`/`to`; custom `from`/`to` accepted for links) | Logs, Dashboard (one range for the whole page), AppSec, Notifications history, Security overview |
| `host_id` | select fed by `/api/hosts` once per session (context) | Logs, Dashboard, Notifications history, Security overview |
| `q` | free text; server decides per endpoint what it matches (never `raw` unless `raw=1`) | Logs, decisions, audit, scenarios, hosts |
| `ip` | exact IP or CIDR | Logs (`remote_ip =`), decisions, whitelist, audit |
| `country`, `scenario`, `origin`, `scope`, `type` | enumerations from the data | decisions, AppSec, Dashboard security |
| `source`, `status`, `method`, `path` | as today, with `waf_audit` in the select | Logs |
| `limit`, `offset`, `total` | same names and same defaults (100 / max 1000) everywhere | every list |

Behaviour rules for the component: 300 ms debounce on text,
`AbortController` on every refetch, state mirrored in the URL
(`useSearchParams`) so links, reloads and bookmarks reproduce the
view, and every page that shows an IP, a domain, a scenario or a
CRS rule id renders it as a link that opens the same `FilterBar`
pre-filled on the target page. "Paste an IP anywhere" then
resolves to the same place: the decisions view with `ip=`, and a
"Logs" link with `ip=` and `range=24h`.

Global search: a header input that classifies the pasted value
client-side (IP/CIDR, domain, CRS id, text) and routes to the
right page with the filter set. No new aggregate endpoint is
required for the first version; the existing lists already
accept the fields. A cross-entity `GET /api/search` is a later
option if the routing version proves insufficient.

Terminology to standardise (UI + JSON): **decision** is the
CrowdSec object; the UI calls a `type=ban` decision a **ban**
and the action "Unban"; **blocked request** is any 403/429 at
the edge; **WAF alert** is a CrowdSec AppSec alert; **event** is
a log row; **notification** is a delivery. `alerts_critical_24h`
goes away or gets a real definition.

## 5. Prioritised proposal

Effort: S (< 1 day), M (1-3 days), L (> 3 days). Risk is
regression risk to security behaviour (bans, reconcilers,
AppSec, auth), which none of these items touch by design.

| # | Change | Usability impact | Effort | Risk | Scope |
|---|---|---|---|---|---|
| 0 | Break the Dashboard refetch loop: `useCallback` for `onLoaded` (or drop it from the effect deps and report `lastUpdated` from the data) | stops ~12 req/s per open dashboard tab; CPU on a 2-core LXC | S (one line) | none | frontend |
| 1 | `RecentErrors` bounded to 24 h as two indexed sub-selects (`UNION ALL`) | Dashboard health card 21-25 s -> ms | S | low | backend, no schema |
| 2 | Security overview: one grouped query for all hosts instead of 3 x N | 30 s -> ms | S | low | backend, no schema |
| 3 | Dashboard cache: serve stale + refresh in background (stale-while-revalidate), single-flight per key, warm at boot, 30 s refresh ticker for `overview` + `health` + default `traffic`/`security` | first paint from cache every time | M | low | backend, no schema |
| 4 | Cert probe results cached 5 min and shared by `/certs`, `overview`, `health` (one probe pass instead of three) | Certificates 1-3 s -> ms; removes 38 TLS dials per dashboard open | S | low | backend, no schema |
| 5 | 7d ranges: rewrite traffic/stats timeseries as covering-index counts per bucket and status class; p95 from a bounded sample; cap `q` LIKE on `raw` to <= 24 h unless `raw=1` | 7d 120 s -> seconds, panel no longer stalls | M | low | backend, no schema |
| 6 | Read/write split: keep the single writer `*sql.DB` (documented) and open a second read-only pool (`mode=ro`, 2-4 conns) for GET handlers | slow reads stop blocking other reads and the ingestor | M | **medium** (documented architecture decision in `storage.md`; needs operator OK; smoke: concurrency probe above must show p99 < 50 ms during a cold health recompute) | backend, no schema |
| 7 | Frontend first paint: keep `/auth/me` result in memory across routes (one fetch per session), remove the `onLoaded` double fetch, render last-known dashboard data from `sessionStorage` under a "refreshing" badge, real skeletons instead of "loading..." | no blank screen between pages; dashboard paints < 1 s on revisit | S-M | low | frontend |
| 8 | `FilterBar` + URL state + debounce + abort; Logs honours `q`/`status`/`path`/`ip`; `waf_audit` in source select; single range picker with the same values everywhere; `search` -> `q`, `total` everywhere | one filter model; links from Dashboard/Certs work | M | low | frontend + small backend aliases |
| 9 | Threats: server-side pagination (`limit`/`offset`, default 100, same envelope as `/security/decisions`), case-insensitive `q`, geo enrichment only for the page, poll only the page in view; `/security/countries` without inline CIDRs (separate `?cidrs=1`) | page settles in < 1 s instead of never; 7.2 MB -> ~50 KB per refresh; 770 KB -> 2 KB | S | low | backend + frontend; **promote to v1.3.38** |
| 10 | Merge the two decision tables into one component (Banned IPs tab and Threats share it); "Unban" everywhere; move "Add manual ban" and country bans next to it | one place for bans | M | low (same endpoints) | frontend |
| 11 | Navigation by intent: **Now** (Dashboard, Threats, Logs), **Protect** (Hosts, Target groups, Security policy = Banned IPs / Whitelist / Countries / Scenarios / AppSec tuning, Certificates), **Operate** (Notifications, Backup, System, Settings); tab state in URL; breadcrumbs + `document.title`; HostSecurity Save returns to origin | "where do I look" answered by the menu | M | low | frontend |
| 12 | WAF signal coherence: either wire the Coraza audit log so `waf_audit` is populated, or feed the Dashboard security section and Security overview from LAPI alerts (what AppSec already does) and retire the empty `waf_audit` paths + Logs preset | one truth for "is the WAF doing anything" | M | medium (touches AppSec data path; upstream pre-flight needed) | backend + frontend; operator decision |
| 13 | Log hygiene: drop `health_checker.active` lines at ingest (93 % of `caddy_error`), stop storing `raw` for access rows by default (keep a setting), `ANALYZE` after each retention run, purge expired sessions | DB 1.7 GB -> ~300 MB at the same row cap; every scan 4-5x cheaper | M | low-medium (changes what Logs can show for old rows) | backend; `raw` policy is a product decision |
| 14 | Hourly rollup table for traffic/stats (7d/30d in ms without visiting rows) | true 30-day dashboards | L | low | **schema (migration 034)**; only if 5 + 13 are not enough |

Item 0 is a bug, not a design choice, and goes first. Items 1-5 and 7 make the dashboard paint in under a second from
cache and remove the two-minute stalls without touching the
schema or any security path. Item 6 is the one architectural
change and is the only item that needs an explicit decision
before implementation. Items 12-14 are product decisions and
are listed so they are not forgotten, not proposed for the
first release.

## 6. What NOT to touch, and why

- **Reverse-sentinel files** (`/data/shared/argos-*.json`,
  `argos-*.txt`, `argos-managed-profiles.yaml`) and their
  readers/writers: they are the only channel between the panel
  (as `nobody`) and `setup-appsec.sh` (as root). Any cache or
  filter refactor must keep `mtime`-based invalidation intact.
- **Async-job pattern** (`country_expansion_jobs`, JobRunner,
  boot-time recovery): a UI move of the country-bans section is
  fine; the submit/poll contract and the 1 s job polling stay.
- **CAPI alert shape** for range bans (1 alert, N decisions) and
  the LAPI client emit paths (`AddRangeDecisions`, revoke by
  `origin=`): strikes 4, 8 and 9 live here.
- **Migrations**: schema is frozen since 033. Items 1-13 need no
  migration. If 14 is approved it is a single additive migration
  with the rollback test extended; nothing rewrites
  `log_entries`.
- **Drift detector and country reconciler tickers**, bouncer
  polling, AppSec mode switching, ForwardAuth cache, session
  and TOTP flows: not part of a UI/performance release; any
  change there is a separate release with its own smoke.
- **Bootstrap Caddyfile and compose files**: the only compose
  change worth considering is out of scope here (project naming
  in 1.1) and is the operator's call.
- **`SetMaxOpenConns(1)` for the writer**: keep it. Item 6 adds
  a reader pool beside it; it does not remove the single writer.

## 7. Proposed scope for the first release (v1.3.38, "dashboard paints in < 1 s")

Backend (no schema):

1. `RecentErrors` bounded + `UNION ALL` (item 1).
2. Security overview grouped query (item 2).
3. Dashboard cache with stale-while-revalidate, single-flight,
   boot warm-up and background refresh (item 3).
4. Shared 5 min cert-probe cache (item 4).
5. 7d traffic/stats via covering-index counts; `q` on `raw`
   bounded (item 5).

Frontend:

0. Fix the `onLoaded` refetch loop (item 0). Smoke: open `/` in
   headless Chromium for 60 s after the page settles and assert
   fewer than 10 `/api/dashboard/overview` requests.
6. One `/auth/me` per session; no blank screen on route change;
   dashboard last-known data from `sessionStorage` + skeletons
   (item 7).
7. Threats pagination (item 9): `/api/threats/decisions` returns
   `{decisions, total, limit, offset}`; the page requests 100 at
   a time. Smoke: response < 100 KB and page settles < 2 s with
   the CAPI blocklist enrolled.

Smoke (EFFECT, prod density):

- `scripts/smoke/dashboard-latency.sh`: after 40 s idle,
  `GET /api/dashboard/health`, `/overview`, `/security/overview`
  each < 1 s; `traffic?range=7d` and `logs/stats?from=<7d>`
  < 5 s; concurrent `/api/hosts` p99 < 50 ms during a forced
  cache miss. Run against `~/argos-prod` before tag.
- Capture: `dashboard-overview.png` / `dashboard-security.png`
  before/after via `scripts/capture/run.sh`.

Explicitly out of this release: item 6 (reader pool) unless the
operator approves the architecture change, and everything from
item 8 onwards (v1.3.39 filters, v1.3.40 navigation).

## 8. Browser paint timing (headless Chromium, 1440x1080, from the LXC)

Method: Playwright Chromium (the capture toolchain's own
browser) logs in once, then navigates route by route with all
server caches warm. `shell` = header rendered; `settled` = no
"loading..." text left and network idle (cut off at 120 s);
`API calls` = requests to `/api/*` seen until settled. A second
pass with 35 s idle before each route (cold caches) was started
and **aborted**: the first pass alone pushed the 2-core LXC to a
load average of 11 while the Threats page rendered, so the cold
pass was not worth the risk to prod. Cold server costs are
already in section 3.1.

| Route | shell | settled | API calls | What dominates |
|---|---|---|---|---|
| `/threats` | 0.16 s | **> 120 s (probe cut off at 329 s)** | 9 | 24,060 decisions (CAPI blocklist) rendered as one table with no pagination: 7.2 MB JSON, tens of thousands of DOM rows, geo cell each; re-fetched every 15 s and on every keystroke |
| `/` Dashboard | 0.17 s | **never** (probe cut off at 240 s) | **2,896** | refetch loop (section 0); tab never goes idle |
| `/security/hosts` | 0.10 s | **39.8 s** | 8 | `security/overview` cold (section 3.1); page shows nothing until it returns |
| `/certificates` | 0.08 s | 5.3 s | 6 | `/api/certs` TLS probes, no cache |
| `/logs` | 0.08 s | 3.0 s | 8 | `logs` + `logs/stats` (1 h) + presets; 200 KB of `raw` for 100 rows |
| `/appsec` | 1.13 s | 1.9 s | 12 | chunk + status + metrics |
| `/security` | 0.11 s | 1.8 s | 7 | decisions page 100 + drift + check-self |
| `/hosts` | 0.56 s | 1.1 s | 16 | includes stray dashboard-loop requests still in flight from the previous route |
| `/system` | 0.57 s | 1.1 s | 10 | five independent cards |
| `/target-groups`, `/notifications`, `/backup` | 0.06-0.14 s | 0.68-0.70 s | 6 | `/auth/me` + layout probes + one list call; the 0.7 s floor is the route-change round trip (`/auth/me`, blank screen, chunk, data) |

The 0.7 s floor on trivially cheap pages is the cost of
`ProtectedRoute` re-fetching `/auth/me` and blanking on every
navigation plus the three layout probes; item 7 removes it.

Threats belongs with item 9 (server pagination) but deserves its
own line in the first release: with the community blocklist
enrolled, the page is unusable as shipped and the 15 s poll
keeps a 7.2 MB download plus a full re-render going in the
background.

### 8.1 Observations on the host during the probe

Load average went from ~2.5 to 11.5 (2 vCPU) while Chromium
rendered `/threats`; the panel container stayed at 0.3 % CPU
and ~240 MB. The LXC memory limit was raised from 2,048 MB to
4,048 MB during the review (observed at 20:46 UTC); the numbers
in section 1 describe the 2 GB state at the start.

## 9. Status after v1.3.38.x (2026-09-26)

Six releases, v1.3.38.0 to v1.3.38.5, all deployed with
`make deploy-prod` and verified on prod (`verify-deploy`,
`deploy-rebuild.sh`). No schema change in any of them; the schema
is still frozen at migration 033. Numbers below are the tag
messages and release notes, all measured on prod unless marked
"demo" (browser runs stay off prod by operator rule).

### 9.1 Resolved in v1.3.38.x

| Finding (section / item) | Before (1.3.35) | After | Closed by |
|---|---|---|---|
| Dashboard refetch loop (0, 3.2, 8; item 0) | 1,293 `GET /api/dashboard/overview` in 60 s with one tab open (2,896 in 240 s headless) | 2 in 60 s (the 30 s auto-refresh); `dashboard-refetch-loop.sh` | v1.3.38.0 |
| Dashboard health cold (0, 3.1; item 1) | 21-25 s cold, 37 s cold disk | 0.044 s cold: `RecentErrors` bounded to 24 h as two indexed sub-selects | v1.3.38.1 |
| Security overview cold, page blank until then (0, 3.1, 8; item 2) | 30-44.8 s | 0.003 s cold: one grouped query for all hosts | v1.3.38.1 |
| Blocking 30 s cache, no warm-up, no last-known state (2.3 #6, 3.2; item 3) | every cache expiry recomputed inline for the caller | stale-while-revalidate, single-flight per key, four default views pinned and refreshed in the background: `X-Argos-Cache: hit` in 0.6-0.8 ms at +60 s after boot with nobody in the panel; panel at rest 1.9 % CPU. The v1.3.38.4 finding (a pinned value served `stale` by a hair under contention because the ticker fired every TTL) is closed: refresh at 4/5 TTL, `hit` on prod under a concurrent 7 d smoke | v1.3.38.2, v1.3.38.5 |
| Three TLS probe passes per dashboard open, `/api/certs` uncached (2.2, 3.1; item 4) | `/api/certs` 0.93-3.0 s every call; 38 TLS dials per dashboard open | one shared 5 min probe pass for certs, overview and health; `/api/certs` 1.4 ms, last event on demand in 0.10 s | v1.3.38.2 (probe cache), v1.3.38.3 (certs list) |
| Boot path: retention purge before listen, a long DELETE holding the connection (3.3) | boot-to-listen 1.75 s; `/api/hosts` max 24.7 s behind a purge | 0.139 s; purge deferred 120 s after listen, batched 5,000 rows / 100 ms; `/api/hosts` across the purge p50 1.3 ms, max 0.31 s; `panel-boot.sh` | v1.3.38.3 |
| 7 d ranges freeze the panel for two minutes (0, 3.1, 3.5; item 5) | `traffic?range=7d` 52.8-119.5 s, `logs/stats` 7 d 35.4-120 s, `logs/timeseries` 27 s | 1.83 s, 1.18 s, 0.74 s cold on the existing covering indexes; figures no index carries (durations, paths, bytes) are computed on the newest 24 h and the card says so; `range-7d-latency.sh`. A bridge until the rollup (9.2) | v1.3.38.4 |
| Threats: 24k rows in the DOM, 7.2 MB per 15 s and per keystroke, never settles (0, 3.1, 8; item 9) | 7.2 MB per response; > 120 s to settle; load 11 on the host while rendering | server-paged 100 rows, every filter server-side (origin, type, search, ip, country, scenario), only the page geo-enriched, refresh only of the visible page and only while the tab is visible: 30,062 B per response on prod (operator's tab, 24k decisions), 180 KB per 60 s; demo: first rows 2.1 s -> 0.3 s, hidden tab 0 requests; `threats-page-bytes.sh` | v1.3.38.5 |
| Threats search case-sensitive; "whitelist" button that removes a ban (2.2, 4.1) | | case-insensitive; button reads `unban` with an explicit confirmation | v1.3.38.5 |
| Blank screen and `/auth/me` on every route change, 0.7 s floor (2.1, 8; item 7) | 1-2 frames without the Layout header per route; `/auth/me` asked 3 times over 6 route changes | the real cause was the `Suspense` outside `<Routes>` replacing the whole Layout while a chunk loaded (`ProtectedRoute` was already kept mounted across Shell routes; only `/appsec` remounted it). Suspense now inside the Layout: 0 blank frames over 6 route changes; `/auth/me` once per session, in memory, dropped on logout and 401 (demo) | v1.3.38.5 |
| "loading..." per section, no last-known data (2.3 #6; item 7) | | skeletons only for a view the session never had; Dashboard, Threats, Security overview and Logs keep their last response in memory keyed by query and refresh behind it (in memory rather than `sessionStorage`: it goes away with the session) | v1.3.38.5 |
| `go vet` red (atomic copy in `client_test.go`) | | green and gated before every commit | v1.3.38.1 |
| Anomaly 1.1 #2: image pin vs running image | pin 1.3.35.4, container 1.3.35 | every deploy verified (`verify-deploy`, `deploy-rebuild.sh`); running = pin = 1.3.38.5 | v1.3.38.0 onwards |
| Anomaly 1.1 #3 / #4: disk 91 %, 2 GB RAM | 2.5 GB free; page cache evicted by any DB copy | 80 % used, 5.3 GB free; LXC at 4,048 MB, 3.2 GB available | operator, 2026-09-25 |
| Friction 2.3 #6 "open the panel and see if things are fine" | 21-25 s | every default view from memory in under 1 ms after any idle | v1.3.38.2 |

Cron and probe items from section 2.1 / 3.3 are in this table: the
boot retention cron (v1.3.38.3) and the per-page TLS probe passes
(v1.3.38.2) are closed; the `check-self` 60 s poll and the
`appsec/status` 30 s probe stay as measured (0.13-0.19 s each) and
are listed under open.

### 9.2 Open

| Item | State on 2026-09-26 | Planned |
|---|---|---|
| 12 WAF signal coherence: `waf_audit` is a dead source (0, 2.2, 2.3 #4) | PHASE 0 done 2026-09-26: every host has the per-host Coraza WAF off since 2026-04-25 16:29 (the same minute `waf-audit.log` was last touched, 0 bytes); the live Caddy config has no `waf` handler, only `crowdsec` + `appsec` on 17 hosts; the chain ingestor -> tailer -> `waf_audit` is intact but has no producer. The WAF that blocks is CrowdSec AppSec (block mode since 2026-04-26): 1,127 `waf` alerts in LAPI over 8 days, 261 blocked in the last 24 h, while the Dashboard says "No WAF events in range" and Security overview "Blocked 24h: 0" | v1.3.39 |
| 6 read/write split (reader pool `mode=ro`) | not started; documented architecture decision in `storage.md`, needs the operator's OK; smoke defined in section 5 | v1.3.40, with the rollup, if approved |
| 13 log hygiene + retention: drop `health_checker.active` at ingest (93 % of `caddy_error`), `raw` policy, `ANALYZE` after purge, purge expired sessions (67 rows, never purged) | not started; effective retention is still ~7 days (`max_entries` 500k hit before 30 days) | v1.3.40 |
| 14 hourly rollup (migration 034) so 7 d and 30 d are exact and cheap | not started; v1.3.38.4 is the bridge | v1.3.40 |
| Purge `SELECT COUNT(*)` over 500k rows before each retention run (deferred in v1.3.38.3/.4) | open | v1.3.40 |
| Threats Until column shows `expired` for imported decisions (v1.3.38.5 known issue) | open; hypothesis: the bouncer endpoint returns `duration` and no `until`, so `Decision.Until` is the zero time (likely every row, not only imported ones) | v1.3.39.x, small |
| 8 `FilterBar`, URL state, debounce everywhere, Logs honouring `q`/`status`/`path`/`ip`, `waf_audit` in the source select, `search` -> `q`; `/security/countries` without inline CIDRs (770 KB) | not started (Threats got its own debounce and server filters in v1.3.38.5) | after v1.3.40; was "v1.3.39 filters" in section 7, displaced by the WAF item |
| 10 one decisions table for Banned IPs and Threats; 11 navigation by intent, tab state in URL, breadcrumbs, `document.title` | not started | after v1.3.40; was "v1.3.40 navigation" in section 7 |
| `check-self` 60 s poll and `appsec/status` 30 s live probe on every page (2.1) | as measured, 0.13-0.19 s per call | unscheduled |
| Anomaly 1.1 #1: compose project name inverted (`argos-edge` is prod) | operator decision 2026-09-25: no rename; recorded in `CLAUDE.md` and memory | closed as a decision |
| Anomaly 1.1 #1: orphan `argos-crowdsec-init` container and unprefixed `argos_*` volumes | untouched | operator's call |

### 9.3 Prod resources after five releases (baseline for v1.3.40)

Measured 2026-09-26 10:28 UTC+2 on the prod LXC with the panel at
rest (no tab open), panel binary 1.3.38.5 started 07:51:03Z.

| Resource | Value | Section 1 (2026-09-25) |
|---|---|---|
| Panel container, at rest (3 samples, 3 s apart) | 0.21-0.32 % CPU, 59-75 MB of 512 MB | 0.3 % CPU, ~240 MB (1.3.35 during the review) |
| Caddy container | 0.2-1.1 % CPU, 49 MB of 256 MB | |
| CrowdSec container | 0-23 % CPU (bursty), 231 MB of 256 MB (90 % of its cap) | 206-228 MB |
| Host | 2 vCPU, 4,048 MB RAM, 794 MB used, 3,253 MB available; load ~3.0 | 2,048 MB then 4,048 MB; load ~2.5 |
| Root disk | 28 GB, 21 GB used, 5.3 GB free (80 %) | 91 %, 2.5 GB free |
| `argos.db` | 1,720,086,528 B (1.72 GB) + WAL 8.1 MB; `log_entries` 501,857 rows: `caddy_access` 480,052, `caddy_error` 21,799, `audit` 6, `waf_audit` 0; oldest row 2026-09-19 (~7 days) | 1.72 GB, 502,297 rows |
| Volumes | `argos_prod_backups` 1.92 GB (14 nightly), `argos_prod_caddy_logs` 159 MB, `argos_prod_crowdsec_data` 100 MB | backups ~1.75 GB |
| Smoke scripts | 24 in `scripts/smoke/`; 23 EFFECT PASS on prod, 1 gated on operator credentials (`auth-flow.sh`), 1 legacy skip (`country-block.sh`) | 18 scripts |
| Deploy | `make deploy-prod` peak load 4.3-5.6 with `BUILD_PARALLELISM=1`; panel healthy 10 s after recreate | 9.7 on 1.3.38.2 |

What v1.3.40 has to move: the DB size (`raw` is ~1.4 KB of every
access row; item 13), the 7 d cost model (rollup; item 14), the
CrowdSec container's memory headroom (26 MB under its cap, not a
panel item but the next thing to fail on this host), and the
reader pool decision (item 6).
