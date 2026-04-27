# Demo stack

A standalone argos-edge environment that runs in parallel with an
existing `argos-prod` deployment on the same host without ever
touching it.

## What it's for

Capturing screenshots for `docs/screenshots/`. Demoing argos to
someone without giving them prod access. Trying out new features
against a populated DB without polluting prod.

## Non-interference contract

Demo and prod share an image (`argos-prod-argos:<version>`) but
otherwise share **nothing**:

| | argos-prod | argos-demo |
|---|---|---|
| Containers | `argos-prod-panel` / `-caddy` / `-crowdsec` | `argos-demo-panel` / `-caddy` / `-crowdsec` |
| Volumes | `argos_prod_*` | `argos_demo_*` |
| Network | `argos_prod_net` | `argos-demo-net` |
| Panel port | `0.0.0.0:9180` | `127.0.0.1:9181` |
| Caddy ports | `0.0.0.0:80`, `0.0.0.0:443` | `127.0.0.1:8090` |
| CrowdSec ports | container-network only | container-network only |
| DB | `/var/lib/docker/volumes/argos_prod_data/...` | `/var/lib/docker/volumes/argos_demo_data/...` |
| LAPI | inside `argos_prod_net` | inside `argos-demo-net` |

The demo's panel is bound to `127.0.0.1` so it never leaks onto the
LAN; reach it from a remote workstation via SSH tunnel
(`ssh -L 9181:localhost:9181 host`).

## Bring it up

```bash
cd ~/argos-edge

# Build the panel image (only needed when argosVersion has changed):
make build-prod-image

# Materialise ~/argos-demo/, generate .env, compose up, seed:
scripts/demo/init.sh
```

You'll get:

```
demo stack ready
panel:  http://localhost:9181
login:  demo / demo1234
```

The panel comes up populated with 8 hosts, 5 country bans, 4
whitelist entries, 15 audit events, 3 notification channels, drift
state, AppSec tuning, and 10 banned IPs in CrowdSec LAPI — every
panel surface looks "real".

All seeded data is RFC 5737 IP space (`192.0.2.x`, `198.51.100.x`,
`203.0.113.x`), `*.example.{com,org,net}` hostnames, and
obviously-fake credentials. Every row carries a `demo:` marker in
a name/reason/value field.

## Tear it down

```bash
# Default: removes containers + volumes, keeps ~/argos-demo/ for
# fast re-init.
scripts/demo/teardown.sh

# Full cleanup: also removes the materialised dir.
scripts/demo/teardown.sh --purge
```

Argos-prod is untouched: the teardown script does a sanity-check at
the end that all `argos-prod-*` containers are still running.

## Capturing screenshots

The 13 panel surfaces that need fresh post-v1.3.20 captures (from
the v1.3.34 deferred screenshot list) are all populated:

1. `/security/banned` — Banned IPs tab (10 RFC5737 IPs, mix of CAPI
   + cscli sources)
2. `/security/whitelist` — 4 entries with `demo:` reasons
3. `/security/activity` — 15 audit events spanning 7 days
4. `/security/scenarios` — populated; `crowdsecurity/http-bf-
   wordpress_bf` is in `appsec.disabled_scenarios`
5. `/security/appsec` — sliders read from
   `appsec.tuning.{inbound,outbound}_threshold` (22 / 5)
6. Drift indicators — `appsec.scenarios.drift_state.drift_detected
   = true` so the amber banner + per-tab dot are visible
7. Country bans Settings section — 5 countries (BR, CN, KR, RU, IR)
   with realistic CIDR counts
8. Host edit modal — most hosts have `auth_required` and/or
   `true_detect_mode` set so the checkboxes render checked
9. DETECT badge on hosts list — admin / grafana / vault hosts
10. Notification channels — Telegram / Webhook / Email all visible

The `v1.3.34.3` version pill renders in the header; the `Build`
card on `/system` shows version + commit + built timestamp.

## Re-seeding

The seed CLI is idempotent for everything except the activity log.
Re-running `init.sh` (or `docker exec argos-demo-panel
ARGOS_DEMO_SEED=1 /argos demo seed --yes`) leaves hosts / countries
/ whitelist / channels / settings unchanged but appends 15 new
activity rows. Useful for capturing "the activity tab fills up over
time" screenshots.

To wipe just the seeded data without re-creating the stack:

```bash
docker exec argos-demo-panel /argos demo clear --yes
```

This removes every row tagged with `demo:`. Settings are
deliberately untouched (the demo writes them via `INSERT OR
REPLACE` so the only way to undo them is `teardown.sh` which nukes
the volume).

## Triple safety: how the seed CLI refuses prod

The seed CLI inside the panel binary won't run unless ALL THREE
hold:

1. `--yes` flag is passed.
2. `ARGOS_DEMO_SEED=1` env var is set.
3. `ARGOS_DB_PATH` does NOT contain `argos-prod`.

`init.sh` sets all three. A copy-paste of `argos demo seed --yes`
into a prod container shell would fail at gate 2 (env var unset)
and gate 3 (path contains `argos-prod`) — twice over.
