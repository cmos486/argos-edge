# Components

Three containers, one docker network, one persistent volume per
container. Nothing else is required to run argos.

```mermaid
flowchart LR
    subgraph internet[Internet]
      client[Client]
    end
    subgraph host[Host (LXC / VM)]
      subgraph bridge[docker bridge: argos_net]
        caddy[Caddy 2<br/>TLS, HTTP/3, WAF, bouncer]
        crowdsec[CrowdSec<br/>LAPI + AppSec]
        argos[argos panel<br/>Go + embedded SPA]
      end
      caddy_data[(caddy_data)]
      crowdsec_data[(crowdsec_data)]
      argos_data[(argos_data<br/>argos.db + backups + geoip)]
    end

    client -->|443 / 80| caddy
    caddy -->|reverse_proxy| upstream[Upstream services]
    caddy -.->|admin API :2019| argos
    caddy -.->|bouncer poll :8081| crowdsec
    caddy -.->|AppSec HTTP :7422/:7423| crowdsec
    argos -.->|LAPI :8081| crowdsec
    caddy --- caddy_data
    crowdsec --- crowdsec_data
    argos --- argos_data
```

Solid arrows are data-plane traffic (public requests + upstreams).
Dashed arrows are control-plane hooks between containers.

## Caddy

Reference version in `docker-compose.yml`. Compiled with:

- `caddy-crowdsec-bouncer` — reads decisions from LAPI every 15 s
  (tunable), blocks banned IPs before any other handler fires.
- `caddy-appsec` — OPTIONAL module that proxies a sub-request to
  the CrowdSec AppSec HTTP listener for inline WAF.
- Standard modules: `caddy2`, `http`, `reverse_proxy`, TLS + ACME.

Configured entirely through the admin API at `:2019`, reachable
only from the argos container over the docker bridge. The panel
never writes Caddyfile text; it POSTs JSON config to `/load`.

Bootstrap Caddyfile (used only for the admin API setup) lives in
the repo; the reconciler takes over after first boot.

## CrowdSec

Two subsystems in one container:

- **LAPI** — authoritative decision store + scenario runner + log
  parser. Reads Caddy's access log (bind-mounted), produces
  decisions when scenarios match. SQLite-backed.
- **AppSec component** — separate HTTP listener that accepts
  sub-requests from Caddy and returns a verdict. Runs Coraza with
  the OWASP CRS rule set. Two listeners: `:7423` (detect) and
  `:7422` (block).

The panel talks to LAPI via `machine` credentials to show /
create / delete decisions.

## argos panel

Single Go binary, scratch-based Docker image. Internal subsystems:

```mermaid
flowchart TB
    subgraph argos[argos container]
      sqlite[(SQLite<br/>/data/argos.db)]
      api[HTTP API + embedded SPA<br/>:8080]
      reconciler[Caddy reconciler]
      drift[Drift detector<br/>60s ticker]
      countryRecon[Country reconciler<br/>5min ticker]
      jobRunner[Country JobRunner<br/>single-worker mutex]
      publicip[Public IP detector]
      notif[Notifications worker]
      ingestor[Log ingestor<br/>tails caddy logs]
      scheduler[Backup scheduler]
      geoip[GeoIP downloader]
      retention[Retention cron]
    end
    api -- writes/reads --> sqlite
    api -- triggers --> reconciler
    api -- submits --> jobRunner
    reconciler -- JSON /load --> caddyAdmin[Caddy admin API]
    drift -- read /crowdsec-state mount --> crowdsecConfig[crowdsec config volume]
    drift -- write drift_state --> sqlite
    countryRecon -- LAPI count by origin --> lapi[CrowdSec LAPI]
    countryRecon -- UPDATE state --> sqlite
    jobRunner -- N decisions per call --> lapi
    publicip -- HTTPS --> external_ipify[ipify.org]
    notif -- reads events --> sqlite
    notif -- sends --> external[Webhook / SMTP / Telegram / Web Push]
    ingestor -- tail --> caddyLogs[Caddy log files]
    ingestor -- batch INSERT --> sqlite
    scheduler -- VACUUM INTO + tar --> backupDir[/data/backups]
    geoip -- download mmdb --> geoipDir[/data/geoip]
    retention -- DELETE old --> sqlite
```

Each of the background goroutines is bounded:

| Goroutine | Bound | Owner |
|---|---|---|
| Caddy reconciler | one trigger per host change | `internal/reconciler/reconciler.go` |
| **Drift detector** (v1.3.27) | every 60 s | `internal/security/drift/drift.go` |
| **Country reconciler** (v1.3.33) | every 5 min | `internal/security/country/reconciler.go` |
| **Country JobRunner** (v1.3.31) | single-worker mutex; one expansion at a time | `internal/security/country/jobs.go` |
| **Public IP detector** (v1.3.23) | every 1 h | `internal/security/publicip/publicip.go` |
| notifications worker | N workers, chan-buffered queue | `internal/notifications/worker.go` |
| log ingestor | one tail + one writer, channel-buffered | `internal/logs/ingestor.go` |
| backup scheduler | one tick per cron match | `internal/backup/scheduler.go` |
| geoip downloader | one run per month cron + boot | `internal/geoip/downloader.go` |
| retention cron | every 6 h | `internal/logs/retention.go` |
| OIDC pending sweeper | every TTL/2 | `internal/oidc/flow.go` |
| TOTP challenge sweeper | every TTL/2 | `internal/totp/challenge.go` |
| ForwardAuth cache sweeper | every 30 s | `internal/api/forward.go` |

Shutdown: every goroutine respects the main context; a SIGTERM
gives them up to 10 s to drain before the binary exits.

### Reconcilers verify what

> Anchor: `#reconcilers-verify-what`. Three different goroutines
> each catch a different drift surface.

Three different goroutines each catch a different drift surface:

- **Drift detector** (`/api/security/drift`) compares the panel's
  `appsec.disabled_scenarios` setting + `appsec.inbound_threshold`
  / `outbound_threshold` against the actual filesystem state in
  `/etc/crowdsec/scenarios/` and `/etc/crowdsec/appsec-rules/
  argos-tuning.yaml`. Surfaces: the `/security/scenarios` and
  `/security/appsec` tabs render an amber "drift detected" banner
  when the panel intent doesn't match the running config.
- **Country reconciler** compares the panel's
  `country_ban_expansions.cidr_count` against the LAPI's actual
  decision count for `argos-country-XX` origin. Flips
  `state='drifted'` when the divergence exceeds 1%. Defensive
  layer for the v1.3.31-era flush-cap incident (which v1.3.33's
  alert-shape fix addressed at the root); covers any future
  drift cause not already prevented at emit time.
- **Country JobRunner** isolates the worker side of the async
  expansion endpoint. Single-worker mutex serialises concurrent
  POSTs (queueing via `state=pending`), preserves boot-time
  recovery (any `pending` / `running` row from a prior process
  transitions to `failed` with `error_message='panel restarted'`).

### Smoke verification

Each panel sub-service has a corresponding smoke under
`scripts/smoke/` that asserts EFFECT against a live stack:

| Sub-service | Smoke | Verifies |
|---|---|---|
| Drift detector | `drift-detection.sh` | 12-phase: PATCH disable → wait 65s → drift_detected=true; setup-appsec.sh → wait 65s → drift_detected=false |
| Country JobRunner | `country-expansion-async.sh` | 8-phase async submit → poll → completed; failure path with crowdsec stopped |
| Country alert shape | `lapi-flush-cap.sh` | NG +1 chunk-alert + IR +3 chunk-alerts; no flush cascade |
| Country reconciler | `country-reconciler.sh` | Drift detected after manual cscli mutation; recovery to active |
| Reverse-sentinel (scenarios index) | `scenario-descriptions.sh` | Slimmed file produced; coverage ≥90%; graceful degrade with file removed |

Full matrix: `docs/operations/verification-report.md`.

## The SPA

`frontend/` is a React + TypeScript + Tailwind app built with Vite.
Output lives in `backend/static/` via the go:embed directive and
gets compiled into the binary. There is no separate frontend
container, no CDN, no runtime dependency.

Code-split by route (every top-level page is a React.lazy boundary)
+ by heavy vendor (charts, map, icons, dnd). Initial bundle is
under 220 KiB minified.

## Storage layout

Inside the argos container, `/data` is the `argos_data` volume:

```
/data/
├── argos.db            # single SQLite file, WAL mode
├── argos.db-wal        # WAL sidecar
├── argos.db-shm        # shared memory
├── backups/            # scheduled + manual tar.gz
│   └── argos-backup-20260420-021500.tar.gz
├── geoip/              # DB-IP Lite mmdb files
│   ├── country.mmdb
│   └── asn.mmdb
└── .restore_pending    # present only during a pending restore
```

`caddy_data` under the caddy container holds certs + ACME state.
`crowdsec_data` holds the LAPI DB + parsers + scenarios.

## What NOT in the stack

- **No message broker**. Notifications go straight from event to
  sender inside the worker goroutine.
- **No cache server** (Redis, memcached). Session lookup hits
  SQLite with a per-process cache for ForwardAuth (30 s TTL).
- **No sidecar for off-site backups**. Mirror `/data/backups/`
  externally.
- **No separate metrics endpoint**. `/api/system/health` returns
  JSON; wire it to whatever uptime monitor you run.

## Related

- [Request flow](request-flow.md) — what happens when a client
  request hits the edge.
- [Storage](storage.md) — SQLite mode, migrations, backup
  semantics.
- [Threat model](threat-model.md) — attack surface + mitigations.
