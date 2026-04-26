# Country bans

Block all traffic from one or more countries at the edge by
expanding a country code into the CIDR ranges its IPs occupy and
pushing each as a `scope=Range` decision into CrowdSec. The Caddy
bouncer enforces them like any other ban; the operator UI lets
you add, list, and revoke per country.

This page covers the path from panel toggle to enforcement, the
async job model that runs it, and the reconciler that watches
for divergence.

## Why argos doesn't use `scope=Country` directly

CrowdSec LAPI accepts `cscli decisions add --scope Country
--value BR` and stores it as a Country decision. The
`caddy-crowdsec-bouncer` plugin **does not handle Country
decisions** in either stream or live mode (this is upstream
strike #2 in the eight-strike pattern). A Country decision shows
up in `cscli decisions list` but does nothing at the edge —
matching requests pass with 200.

v1.3.21 worked around this panel-side: read the country's CIDR
list from the GeoLite2 / DB-IP MMDB, push one `scope=Range`
decision per CIDR. Range decisions the bouncer DOES handle
correctly. v1.3.22 added supernet rollup with a /16 floor +
chunked POST so the LAPI doesn't get a 21k-alert single batch.

## How the panel emits to LAPI (v1.3.33 shape)

The expansion writes one alert per chunk-call carrying up to 500
decisions inside the alert's `decisions[]` array. This mirrors
CrowdSec's own community-blocklist shape:

```
country expansion (BR, 5009 CIDRs)
   ↓
Expander chunks at 500-CIDR boundaries → 11 chunks
   ↓
For each chunk:
   POST /v1/alerts with:
     [{
       scenario: "argos: argos-country-BR (+500 ranges)",
       source: { scope: "argos-country-BR", value: "" },
       decisions: [
         { scope: "Range", value: "1.2.3.0/24", origin: "argos-country-BR", duration: "168h", type: "ban" },
         ... (up to 500 entries)
       ]
     }]
   ↓
LAPI inserts: 1 alert + N decisions
```

Net result for BR: **11 alerts** in the LAPI alerts table, 5009
decisions in the decisions table.

### Why this shape matters

Pre-v1.3.33 the panel emitted **one alert per CIDR** (5009
alerts for BR alone). CrowdSec's `flush.max_items: 5000` default
counts ALERTS, not decisions; emitting >5000 alerts triggered a
silent cascade flush that deleted older `argos-country-*` alerts
(and their cascade-deleted decisions). The panel's
`country_ban_expansions` table claimed 8 countries banned; the
LAPI had zero of them active.

v1.3.33's alert-shape restructure fixed the root cause; the
shape now mirrors the only LAPI bulk-insert shape upstream
tested at scale. See the v1.3.33 release notes for the full
incident timeline.

## Async submit + poll (v1.3.31)

A country expansion takes 10-30s for fragmented countries (BR
~5009 ranges, US ~20094 ranges). Synchronous handlers blocked
the operator's HTTP request for the full window and required
the panel to set its `WriteTimeout` to 20 minutes. v1.3.31
swapped the endpoint for an async pattern.

```bash
POST /api/security/countries/{cc}/expand
Body: {"duration": "168h", "reason": "spike from BR"}
```

Returns `202 Accepted` immediately with the new job row:

```json
{
  "id": 12,
  "country_code": "BR",
  "state": "pending",
  "chunks_total": 0,
  "chunks_done": 0,
  "cidr_committed": 0,
  "duration": "168h",
  "reason": "spike from BR",
  "created_at": "2026-04-26T18:16:52Z",
  "created_by": "admin"
}
```

Poll for progress:

```bash
GET /api/security/jobs/{job_id}
```

State transitions: `pending` → `running` → `completed` (or
`failed` with `error_message` populated). The frontend polls
every 1 second and renders a progress bar driven by
`chunks_done / chunks_total` plus the running `cidr_committed`
count.

### Single-worker mutex

The JobRunner serialises concurrent submissions via a global
mutex. If the operator submits BR and TR back-to-back, the
JobRunner accepts both (one becomes `pending`), runs them in
order, and the polling endpoint surfaces each transition. This
prevents two parallel country expansions from fighting for LAPI
WAL locks (the v1.3.22-era contention finding).

### Boot-time recovery

If the panel restarts mid-expansion, any `pending` or `running`
row gets transitioned to `failed` with
`error_message='panel restarted'` on next boot. The operator's
polling client sees the failure and can re-submit.

## Reconciler health check (v1.3.33)

A second goroutine, the **country reconciler**, runs every 5
minutes and compares panel state to LAPI state for each
expansion:

1. Reads `country_ban_expansions.cidr_count` per row.
2. For each, calls
   `crowdsec.Client.CountDecisionsByOrigin("argos-country-XX")`
   against the LAPI cache.
3. If `|panel - lapi| > max(1, panel * 1%)`, transitions the
   row to `state='drifted'`.
4. If the count returns to within tolerance, transitions back
   to `state='active'`.

The state field surfaces in the `/api/security/countries`
response. UI rendering of the drift indicator is queued for a
follow-up release; the API contract is in place.

## Operator workflow

### Add a country

```
Settings → Country bans → enter ISO code → "Add country ban"
   ↓
202 + job row in pending state
   ↓
progress bar shows chunks_done / chunks_total
   ↓
on completion: success toast + decisions visible at the edge
```

The Caddy bouncer's next 15-second poll picks up the new
decisions; from that moment any request from a matching CIDR
gets `403 Forbidden` before reaching upstream.

### Revoke a country

```bash
DELETE /api/security/countries/{cc}
```

Issues `DELETE /v1/decisions?origins=argos-country-XX` to LAPI
(removes every decision tagged with the origin) plus
`DELETE FROM country_ban_expansions` (removes the panel-side
row). Synchronous; <1 second on the operator side.

### List active expansions

```bash
GET /api/security/countries
```

Returns the `country_ban_expansions` rows (with the v1.3.33
`state` field). The Settings UI surfaces this as a table.

## Tuning

`Expander.ChunkSize` defaults to 500 CIDRs per chunk. Lower
values produce more chunks (more alerts) but smaller per-call
LAPI work; higher values do the inverse. 500 was empirically
chosen against LAPI's per-call SQLite write batch behaviour.

`country.DefaultReconcilerInterval` is 5 minutes. Lower for
more aggressive drift detection at the cost of more
ListDecisions calls (which are cached for 15 seconds at the
panel's `crowdsec.Client` layer; only the first call per
window hits LAPI).

## Limitations

- **MMDB version drift**: the panel records the MMDB version at
  expansion time. CrowdSec's monthly MMDB refresh (or DB-IP's
  monthly Lite update) can change the CIDR set for a country.
  The expansion is NOT auto-refreshed; the operator runs
  re-expansion when they care about the new ranges.
- **Bouncer poll interval**: a freshly-expanded country takes
  up to `crowdsec.poll_interval_seconds` (default 15s) to
  reach the bouncer's in-memory store. Requests during that
  window pass.
- **No partial revoke**: revoking a country drops every CIDR,
  not a subset. To exempt one CIDR, use the manual whitelist
  (`/security/whitelist`) — system whitelists are processed
  before bouncer decisions.

## Related

- [CrowdSec](crowdsec.md) — broader IP-ban surface.
- [Reconciler health checks](../architecture/components.md#reconcilers-verify-what) —
  the country reconciler is one of three.
- `scripts/smoke/country-expansion-async.sh` — 8-phase async
  flow smoke (refuses to run with placeholder defaults).
- `scripts/smoke/lapi-flush-cap.sh` — alert-shape verification
  (1 alert per chunk; no flush cascade).
- `scripts/smoke/country-reconciler.sh` — drift detection +
  recovery.
- v1.3.33 release notes for the alert-shape root-cause writeup.
