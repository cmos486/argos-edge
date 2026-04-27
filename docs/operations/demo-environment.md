# Demo environment

A standalone argos-edge stack that runs in parallel with an existing
`argos-prod` deployment on the same host without touching it. Use it
for capturing screenshots, demoing argos to someone, or testing new
features against a populated DB without polluting prod.

## Why standalone

The original problem (v1.3.34 deferred-screenshot list): operator
needed 13 fresh post-v1.3.20 captures, but the live prod stack
contained operator-specific data (real domains, real banned IPs)
that can't be committed to the public docs portal. Spinning a
second stack with **synthetic** data lets the screenshots land in
the public repo without sanitization gymnastics.

## Non-interference contract

By construction, demo and prod share an image
(`argos-prod-argos:<version>`) but otherwise share **nothing**:

| | argos-prod | argos-demo |
|---|---|---|
| Containers | `argos-prod-panel` / `-caddy` / `-crowdsec` | `argos-demo-panel` / `-caddy` / `-crowdsec` |
| Volumes | `argos_prod_*` | `argos_demo_*` |
| Network | `argos_prod_net` | `argos-demo-net` |
| Compose project | `argos-edge` | `argos-demo` |
| Panel port | `0.0.0.0:9180` | `127.0.0.1:9181` |
| Caddy ports | `0.0.0.0:80`, `0.0.0.0:443` | `127.0.0.1:8090` |
| CrowdSec ports | container-network only | container-network only |
| DB volume | `argos_prod_data` (`/data/argos.db`) | `argos_demo_data` (`/data/argos.db`) |
| LAPI | inside `argos_prod_net` | inside `argos-demo-net` |

The demo's panel binds to `127.0.0.1` (not `0.0.0.0`) on purpose so
the demo never leaks onto the LAN. From a remote workstation, reach
it via SSH tunnel:

```bash
ssh -L 9181:localhost:9181 argos-host
# then http://localhost:9181 in the local browser
```

## Bring it up

Single command from the source repo:

```bash
cd ~/argos-edge

# Build the panel image (only needed when argosVersion has changed):
make build-prod-image

# Materialise ~/argos-demo/, generate .env, compose up, seed:
scripts/demo/init.sh
```

Output:

```
demo stack ready
panel:  http://localhost:9181
login:  demo / demo1234
```

Initial seed populates:

| Surface | Count | Source of truth |
|---|---|---|
| Hosts | 8 | `hosts` table — mix of TLS modes + auth_required + true_detect_mode + lan_only |
| Country bans | 5 | `country_ban_expansions` — BR / CN / KR / RU / IR |
| Whitelist | 4 | `security_whitelist` — `198.51.100.x` and `203.0.113.x` |
| Activity log | 15 | `log_entries` (source=audit) — 7-day spread |
| Banned IPs in LAPI | 10 | CrowdSec `decisions` table via `cscli decisions add` |
| Notification channels | 3 | `notification_channels` — Telegram / Webhook / Email |
| AppSec tuning | 2 keys | `settings.appsec.tuning.*` |
| Disabled scenarios | 2 | `settings.appsec.disabled_scenarios` |
| Drift state | 2 | `settings.appsec.{scenarios,tuning}.drift_state` (drift_detected=true so the banner shows) |
| Header version pill | 1 | `/api/system/version` from the v1.3.35 binary |

## Sanitization

Every seeded value is one of:

- RFC 5737 IP space: `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`.
- IANA reserved domain: `*.example.com`, `*.example.org`,
  `*.example.net`.
- Fake credentials: bot token `123456:demo-bot-token-not-real`,
  email `demo@example.com`, webhook URL `hooks.example.com`.
- Marker prefix `demo:` in name / reason / message fields wherever
  the schema permits, so an operator can always grep their DB to
  verify the demo's footprint.

`scripts/check-no-personal-data.sh` runs against the source repo
including `scripts/demo/` and the seed CLI source; the demo never
introduces operator data into committed sources.

## Tear it down

```bash
# Default: removes containers + volumes, keeps ~/argos-demo/ for
# fast re-init.
scripts/demo/teardown.sh

# Full cleanup: also removes the materialised dir.
scripts/demo/teardown.sh --purge
```

The teardown script ends with a sanity check that all
`argos-prod-*` containers are still running. If a prod container
disappeared during the demo lifecycle (which would only happen
under unrelated host trouble), the script logs a WARN line so the
operator notices.

## Capturing screenshots

Once the stack is up at `http://localhost:9181`, the 13 post-v1.3.20
captures from the v1.3.34 deferred list are all reachable:

| Path / element | What's there |
|---|---|
| `/security/banned` | 10 RFC5737 IPs from the LAPI seed |
| `/security/whitelist` | 4 entries with `demo:` reasons |
| `/security/activity` | 15 audit events (last 7 days) |
| `/security/scenarios` | populated; `crowdsecurity/http-bf-wordpress_bf` disabled |
| `/security/appsec` | sliders read 22 / 5 from the seeded tuning keys |
| Drift indicators (banner + amber dot) | `drift_state.drift_detected=true` for scenarios |
| Country bans Settings | 5 countries with realistic CIDR counts |
| Host edit modal `true_detect_mode` | several hosts seeded with it set |
| DETECT badge on hosts list | next to admin / grafana / vault |
| SelfBlockBanner | (skip — would require the operator's IP to actually be banned in the demo LAPI) |
| `host-form.png` | post-v1.3.29 modal layout |
| `appsec-status.png` | v1.3.25 tuning UI shape |
| `threats-decisions.png` | post-v1.3.24 tab move |

The header `v1.3.35` version pill renders to confirm the deployed
binary; the `Build` card on `/system` shows commit + built_at.

## Re-seeding

The seed CLI is **idempotent** for everything except the activity
log:

- Hosts / countries / whitelist / channels: `INSERT OR IGNORE`, so
  re-runs leave row counts unchanged.
- Settings: `INSERT OR REPLACE`, so re-runs overwrite values back to
  the demo defaults (handy if you're tweaking).
- Activity log: each run **appends** 15 rows with current timestamps.
  Useful for capturing "the activity tab fills up over time"
  screenshots.

To wipe just the seeded data without re-creating the stack:

```bash
docker exec argos-demo-panel /argos demo clear --yes
```

This removes every row tagged with `demo:`. Settings are
deliberately untouched (the only way to undo them is `teardown.sh`,
which removes the volume entirely).

## Triple-key safety

The seed CLI inside the panel binary refuses to run unless **all
three** hold:

1. `--yes` flag is passed.
2. `ARGOS_DEMO_SEED=1` env var is set.
3. `ARGOS_DB_PATH` does **NOT** contain the substring `argos-prod`.

`init.sh` sets all three. A copy-paste of `argos demo seed --yes`
into a prod container shell would fail at gate 2 (env var unset)
and gate 3 (path contains `argos-prod`) — twice over.

## Smoke

`scripts/smoke/demo-environment.sh --yes` runs the full lifecycle
end-to-end and verifies the non-interference invariant explicitly:
captures argos-prod baseline (container IDs + StartedAt
timestamps), runs init, asserts demo health + 10 surfaces, asserts
prod baseline unchanged, runs teardown, asserts demo gone, asserts
prod baseline still unchanged.

Self-executed against the live host pre-tag for v1.3.35; PASS.

## Related

- [Deployment](deployment.md) — how `make build-prod-image` produces
  the image both prod and demo run.
- [Documentation audit](documentation-audit.md) — origin of the
  13-screenshot deferral that motivated this scaffold.
- `scripts/demo/README.md` — operator-facing quick reference.
- `backend/cmd/argos/cli_demo.go` — seed CLI source + safety gates.
