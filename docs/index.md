---
title: argos-edge
hide:
  - navigation
---

# argos-edge

**Self-hosted edge gateway for homelabs.** Reverse proxy + WAF + load
balancing + SSO in a single panel. Powered by Caddy, Coraza/OWASP CRS
and CrowdSec.

![Dashboard overview](screenshots/dashboard-overview.png){ loading=lazy alt="Argos panel Dashboard tab showing traffic, attacks by country world map, and top offending IPs" }

## What you get

- **Reverse proxy with Let's Encrypt** on the Caddy 2 runtime, HTTP/3
  included. Add a host from the panel and the cert provisions on the
  next request.
- **Target groups** (AWS-ALB-style) so one public host can round-robin
  across multiple upstreams with active + passive health checks.
- **Inline WAF** using Coraza + OWASP CRS via the CrowdSec AppSec
  component. Switchable between `detect`, `block` and `disabled` at
  runtime, no container restart.
- **Community threat intel** from CrowdSec. IPs already flagged by the
  community get blocked before they reach rules, WAF or upstream.
- **Per-host SSO.** Optional OIDC sign-in (Google, Microsoft, Keycloak,
  Authentik, Authelia) plus ForwardAuth that lets you put any HTTP
  service behind the same session cookie.
- **2FA for local accounts** (RFC 6238 TOTP + recovery codes), with a
  sensible rate limit and a break-glass CLI.
- **Audit log + notifications.** Webhook, email, Telegram and browser
  push channels with a token-bucket rate limiter and throttle-per-rule.
- **Local backups.** Scheduled tar.gz snapshots of the DB + Caddy state
  under `/data/backups/`, SHA-256-tracked, restore via one endpoint.
- **Observable.** Dashboard aggregates, security overview, threats
  list, filterable log browser with SSE tail, GeoIP enrichment.

## Quickstart

```bash
git clone https://github.com/cmos486/argos-edge.git
cd argos-edge
cp .env.example .env
# edit .env: set ARGOS_SESSION_SECRET, ARGOS_MASTER_KEY,
# ARGOS_INITIAL_ADMIN_PASSWORD
docker compose up -d
open http://<lan-ip>:8080
```

End-to-end in under ten minutes: [Quickstart](getting-started/quickstart.md).

## Where to go next

<div class="grid cards" markdown>

- :material-rocket-launch: **[Getting started](getting-started/installation.md)**
    Install, first-run, your first host under a public domain.

- :material-playlist-check: **[Workflows](workflows/index.md)**
    Step-by-step playbooks for the common operational tasks.

- :material-puzzle: **[Features](features/reverse-proxy.md)**
    Reference pages for each subsystem.

- :material-sitemap: **[Architecture](architecture/components.md)**
    Component map, request flow, threat model.

</div>

## Project status

Argos is a solo homelab project, not a commercial product. It powers
production workloads on the maintainer's own infrastructure, but
support is best-effort and the roadmap moves when the maintainer has
time. File issues on
[GitHub](https://github.com/cmos486/argos-edge/issues) and expect a
response, not a SLA.

---

*argos-edge is licensed under [BSL 1.1](https://github.com/cmos486/argos-edge/blob/main/LICENSE).
It converts to Apache 2.0 on 2030-04-20.*
