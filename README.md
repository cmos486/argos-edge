# argos-edge

Self-hosted edge gateway for homelabs. Reverse proxy + WAF + load balancing + Let's Encrypt, unified web panel. Powered by Caddy, Coraza and CrowdSec.

**Status:** early development (Phase 0). Not production-ready, not supported, use at your own risk.

## Why

Nginx Proxy Manager is too simple. Zoraxy lacks WAF. BunkerWeb and SafeLine are great but not quite what I wanted. Argos Edge is a personal homelab project scratching my own itch: a single panel with proxy + real WAF + ALB-style rules + good dashboards.

## Stack

- [Caddy 2](https://caddyserver.com/) as the proxy (TLS, Let's Encrypt, HTTP/3)
- [Coraza](https://coraza.io/) + OWASP CRS as the WAF (Phase 4)
- [CrowdSec](https://www.crowdsec.net/) for community threat intel (Phase 6)
- Go backend, React + TypeScript + Tailwind frontend, SQLite storage

## Quick start

```bash
git clone https://github.com/cmos486/argos-edge.git
cd argos-edge
cp .env.example .env
# edit .env: set ARGOS_SESSION_SECRET, ARGOS_MASTER_KEY, ARGOS_INITIAL_ADMIN_PASSWORD
docker compose up -d
```

Then open `http://<host-ip>:8080` and log in with the credentials you set in `.env`.

## Panel access modes

Phase 9b introduced two access modes, selected via `ARGOS_PANEL_MODE`:

| Aspect | `lan` (default) | `behind_caddy` |
|---|---|---|
| How to reach the panel | `http://<lan-ip>:8080` | `https://$ARGOS_PANEL_DOMAIN/` |
| `:8080` published on host | yes | no (internal only) |
| Cookie `Secure` flag | off | on |
| `SameSite` | Strict (both modes) | Strict |
| HSTS header | not sent | `max-age=31536000; includeSubDomains` |
| Content-Security-Policy | not sent | yes (strict, no external origins) |
| Browser Push | blocked (no HTTPS) | works |
| Bootstrap on first boot | - | auto-creates hosts row + TG pointing at `argos:8080` |

### LAN mode

Nothing to do: `docker compose up -d` starts the panel at `http://<lan-ip>:8080`.

### behind_caddy mode

1. In `.env`:
   ```
   ARGOS_PANEL_MODE=behind_caddy
   ARGOS_PANEL_DOMAIN=panel.example.com
   ```
2. Start the stack with the override file layered on top:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.behind-caddy.yml up -d
   ```
3. The panel auto-registers itself as a host on first boot; Caddy obtains a cert via DNS-01 in ~30s. Visit `https://panel.example.com/`.

Requires Docker Compose v2.24+ (for the `!reset []` YAML tag in the override).

**Breaking change in v0.9.0:** `ARGOS_COOKIE_SECURE` was removed. Cookie secure flag is now derived from `ARGOS_PANEL_MODE`.

## CrowdSec (threat intel)

Phase 7 bundles CrowdSec as a docker-compose service. CrowdSec reads Caddy's access logs and pushes decisions to the panel's UI (`/threats`) and to Caddy's bouncer for enforcement. One-time setup after first `docker compose up -d`:

```bash
# 1. Issue a bouncer API key for Caddy's HTTP bouncer module
docker compose exec argos-crowdsec cscli bouncers add argos-caddy-bouncer
#    copy the printed key

# 2. Register the panel as a CrowdSec "machine" so it can add / delete
#    decisions from the UI (bouncer keys are read-only)
docker compose exec argos-crowdsec cscli machines add argos-panel -a -f /tmp/argos-panel.yaml
docker compose exec argos-crowdsec cat /tmp/argos-panel.yaml
#    copy login + password

# 3. Put all three values in .env:
#      CROWDSEC_BOUNCER_API_KEY=<key from step 1>
#      CROWDSEC_PANEL_MACHINE_USER=argos-panel
#      CROWDSEC_PANEL_MACHINE_PASSWORD=<password from step 2>

# 4. Rebuild so caddy picks up the bouncer key + panel reads new env
docker compose up -d --build
```

Until step 4 runs, the panel starts normally and `/threats` shows a setup banner with the commands above. Caddy serves traffic without enforcement.

To install additional CrowdSec collections:

```bash
docker compose exec argos-crowdsec cscli collections install crowdsecurity/<name>
```

CrowdSec's LAPI listens on `crowdsec:8081` inside the docker network (not published to the host). The default LAPI port 8080 would collide with argos-panel, so we mount `crowdsec/config.yaml.local` to override it.

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md).

## Roadmap

See the phased roadmap in ARCHITECTURE.md. Currently on Phase 0.

## License

MIT
