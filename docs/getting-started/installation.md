# Installation

Argos ships as a set of Docker containers. No standalone binary
distribution; the bundled SPA lives inside the Go image and the
Caddy/CrowdSec runtimes are opinionated enough that extracting argos
from compose is more work than it saves.

## Requirements

- **Docker Engine 24+** and Docker Compose v2. An LXC on Proxmox with
  nested docker support works; so does a bare VM.
- **2 CPU, 2 GB RAM** is comfortable. The panel itself fits in a few
  dozen MB; the floor is Caddy + CrowdSec.
- **~2 GB disk** for the `argos_data`, `caddy_data`, `crowdsec_data`
  volumes plus log rotation headroom.
- **Outbound 80/443** for Let's Encrypt + CrowdSec community pulls
  + GeoIP monthly download from DB-IP.

If you intend to run with `ARGOS_PANEL_MODE=behind_caddy` you also
need a DNS name you control pointing at the host.

## Clone + configure

```bash
git clone https://github.com/cmos486/argos-edge.git
cd argos-edge
cp .env.example .env
```

Open `.env` and set the three mandatory secrets:

```bash
ARGOS_SESSION_SECRET=<32+ random bytes, openssl rand -hex 32>
ARGOS_MASTER_KEY=<exactly 32 bytes, openssl rand -hex 32>
ARGOS_INITIAL_ADMIN_PASSWORD=<strong password>
```

`CLOUDFLARE_API_TOKEN` is optional — leave it blank unless a host
will use TLS mode=dns01 with the Cloudflare provider (a wildcard
cert on a Cloudflare-managed zone, typically). HTTP-01 — the
default for `tls_mode=auto` — does not touch it. Details:
[env vars → CLOUDFLARE_API_TOKEN](../reference/env-vars.md#cloudflare_api_token).

Then decide your panel mode.

## Panel access modes

| Aspect                   | `lan` (default)                 | `behind_caddy`                     |
|--------------------------|---------------------------------|------------------------------------|
| How to reach the panel   | `http://<lan-ip>:8080`          | `https://$ARGOS_PANEL_DOMAIN/`     |
| `:8080` published        | yes                             | no, internal docker bridge only    |
| Cookie `Secure` flag     | off                             | on                                 |
| `SameSite`               | Strict                          | Strict                             |
| HSTS header              | not sent                        | `max-age=31536000; includeSubDomains` |
| CSP                      | not sent                        | sent, `'unsafe-inline'` on script-src |
| Trusts `X-Real-IP`       | no (socket only)                | yes (Caddy sets it)                |
| Intended network         | trusted LAN                     | public internet                    |

### LAN mode

No extra config beyond the three secrets. `ARGOS_PANEL_MODE` defaults
to `lan` so an empty variable picks this path.

```bash
docker compose up -d
```

Open `http://<lan-ip>:8080` and log in with
`ARGOS_INITIAL_ADMIN_USER` (default `admin`) + the password from
`.env`.

### behind_caddy mode

Add the override compose file. It drops the published `:8080` and
wires argos under a Caddy reverse proxy at `ARGOS_PANEL_DOMAIN`. The
panel also gets auto-registered as a host in its own DB on first
boot so Caddy serves it immediately.

```bash
echo 'ARGOS_PANEL_MODE=behind_caddy' >> .env
echo 'ARGOS_PANEL_DOMAIN=panel.example.com' >> .env
docker compose -f docker-compose.yml -f docker-compose.behind-caddy.yml up -d
```

The DNS record for `panel.example.com` must already resolve to the
host *before* the stack comes up, otherwise Let's Encrypt will fail
the HTTP-01 challenge on the first request.

## Volumes

Eight named docker volumes get created automatically. All persist
across `docker compose down` + `up`; all are destroyed by
`docker compose down -v`.

| Volume | Container mount | Contents | In argos backup? | Lose it and... |
|---|---|---|---|---|
| `argos_data` | `/data` in argos | `argos.db` + `/data/geoip/` | **Yes** (the DB) | Everything: hosts, users, settings, audit log, manual cert metadata, notifications history |
| `argos_backups` | `/data/backups` in argos | local tar.gz backups | No (this IS the destination) | Local backup history gone; off-site replica preserves it |
| `caddy_data` | `/data` in caddy (RO mount into argos) | ACME account keys + issued certs | **Yes** (best-effort; see [Backups](../features/backups.md)) | Every ACME cert re-issues on next request; ACME account is regenerated |
| `caddy_config` | `/config` in caddy | Caddy runtime config cache | No (regenerable) | No impact: argos re-pushes the config on next boot |
| `caddy_logs` | `/var/log/caddy` in caddy (RO into argos + crowdsec) | access.log + errors.log (rotated) | No (rotates independently) | Pre-rotation logs lost; rows already ingested into `log_entries` stay |
| `caddy_manual_certs` | `/data/manual-certs` in argos, `/etc/caddy/manual-certs` in caddy (RO) | Plaintext `.crt` + `.key` files for manual-mode hosts | No (DB row has the encrypted key) | No impact: the boot reconciler rematerialises the files from `argos.db` on next startup, provided `ARGOS_MASTER_KEY` is unchanged |
| `crowdsec_data` | `/var/lib/crowdsec/data` | LAPI decisions DB + machine/bouncer credentials | No | Re-enrollment + community feed re-download; regenerate bouncer API key |
| `crowdsec_config` | `/etc/crowdsec` | Installed collections, parsers, appsec config | No | Re-run the boot setup script to reinstall collections |

!!! warning "ARGOS_MASTER_KEY is part of your backup"
    The `ARGOS_MASTER_KEY` in `.env` encrypts every secret the
    panel persists: manual cert private keys, OIDC client secrets,
    SMTP passwords, Telegram bot tokens, VAPID private keys. If
    you restore `argos.db` onto fresh infrastructure but cannot
    produce the original `ARGOS_MASTER_KEY`, every encrypted value
    is **unrecoverable**. Store `.env` (or at minimum this one
    value) in a password manager / secrets store alongside your
    backups.

Back these up with the panel's scheduled-backup feature (see
[Backups](../features/backups.md)) or by copying the volume
contents out of band. The argos backup captures `argos.db` plus a
best-effort snapshot of `caddy_data`; everything else is either
regenerable (`caddy_config`, `caddy_manual_certs`) or out of
scope (`crowdsec_*`, logs).

## Upgrading

```bash
cd argos-edge
git pull
docker compose pull
docker compose up -d
```

Schema migrations run automatically on container start. Upgrade
safety is covered in [Upgrading](../operations/upgrading.md).

## Uninstall / reset

```bash
docker compose down -v
```

`-v` drops the named volumes and you lose your DB, backups and certs.
Run without `-v` to keep the data and merely stop the stack.

## Next

- [First run](first-run.md) — create the first host
- [Quickstart](quickstart.md) — condensed end-to-end
