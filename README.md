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
# edit .env: set ARGOS_SESSION_SECRET and ARGOS_INITIAL_ADMIN_PASSWORD
docker compose up -d
```

Then open `http://<host-ip>:8080` and log in with the credentials you set in `.env`.

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md).

## Roadmap

See the phased roadmap in ARCHITECTURE.md. Currently on Phase 0.

## License

MIT
