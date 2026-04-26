# argos-edge

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/cmos486/argos-edge)](https://github.com/cmos486/argos-edge/releases)
[![Docs](https://img.shields.io/badge/docs-cmos486.github.io-blue)](https://cmos486.github.io/argos-edge/)

Self-hosted edge gateway for homelabs. Reverse proxy + WAF +
load balancing + Let's Encrypt + SSO, unified web panel.
Powered by Caddy 2, Coraza/OWASP CRS and CrowdSec.

**Status:** stable; in active development. Solo-maintained,
homelab-grade. The project does what it does well; it's not a
hyperscaler load balancer or a Kubernetes ingress and doesn't
try to be. See the [docs portal](https://cmos486.github.io/argos-edge/)
for installation, operations, and the per-feature deep dives.

<!-- TODO: post-v1.3.34 capture session — embed dashboard hero shot here -->
<!--   path: docs/screenshots/dashboard-overview.png (already exists; re-take post-v1.3.20 features) -->

## Why

Nginx Proxy Manager is too simple. Zoraxy lacks WAF. BunkerWeb
and SafeLine are great but not quite what I wanted. argos-edge
is a personal homelab project scratching my own itch: a single
panel with proxy + real WAF + ALB-style rules + good
dashboards.

## What you get

- **Reverse proxy with Let's Encrypt** on Caddy 2; HTTP/3
  included. Add a host from the panel and the cert provisions
  on the next request. Multi-provider DNS-01 with encrypted
  credentials.
- **Target groups** (AWS-ALB-style) so one public host can
  round-robin across multiple upstreams with active + passive
  health checks.
- **Inline WAF** using Coraza + OWASP CRS via the CrowdSec
  AppSec component. Switchable between detect / block / disabled
  per host at runtime, no container restart. Per-host CRS rule
  exclusions + custom SecRule text.
- **Per-host `true_detect_mode`** (v1.3.29) — hosts whose
  legitimate traffic triggers AppSec false positives can opt
  out of scenario-based bans while still seeing alerts.
- **Community threat intel** from CrowdSec. Country bans
  expanded panel-side to Range decisions (the bouncer plugin
  doesn't handle Country directly). Async submit + poll for
  big expansions like BR (~5009 ranges).
- **Drift detection** (v1.3.27) — the panel verifies that
  CrowdSec's running state matches what the panel believes is
  set, and surfaces a banner when it doesn't.
- **Per-host SSO.** OIDC sign-in (Authentik, Authelia, Keycloak,
  Google, Okta) plus ForwardAuth that lets you put any HTTP
  service behind the same session cookie.
- **2FA for local accounts** (RFC 6238 TOTP + recovery codes)
  with break-glass CLI subcommands when the operator loses
  both phone and recovery codes.
- **Notifications** (Slack, email/SMTP, Telegram, generic
  webhook, browser Web Push) with per-event rules + rate
  limiting + delivery history.
- **Manual cert uploads** for hosts on closed networks where
  ACME isn't reachable.
- **Backup + restore** via `VACUUM INTO` snapshots; one-click
  schedule + manual + restore-from-upload.
- **Logs browser** over Caddy access + WAF audit + panel
  audit, with retention.

Full feature list + per-feature deep dives: see the
[docs portal](https://cmos486.github.io/argos-edge/).

## Stack

- [Caddy 2](https://caddyserver.com/) — proxy (TLS, Let's
  Encrypt, HTTP/3)
- [Coraza](https://coraza.io/) + OWASP CRS — WAF
- [CrowdSec](https://www.crowdsec.net/) — community threat
  intel + AppSec inline component
- Go backend (single binary, embedded React SPA), SQLite
  storage

## Quick start

```bash
git clone https://github.com/cmos486/argos-edge.git
cd argos-edge
cp .env.example .env
# edit .env: set ARGOS_SESSION_SECRET, ARGOS_MASTER_KEY,
#            ARGOS_INITIAL_ADMIN_PASSWORD
docker compose up -d
```

Then open `http://<host-ip>:8080` and log in with the
credentials you set in `.env`.

For the production-shape setup with TLS + a dedicated panel
domain, see
[Installation → behind_caddy mode](https://cmos486.github.io/argos-edge/getting-started/installation/).

<!-- TODO: post-v1.3.34 capture session — embed login + first-run flow screenshots here -->
<!--   docs/screenshots/login.png (current; may need re-take if login UI changed) -->

## Two access modes

argos ships two operating shapes selected via
`ARGOS_PANEL_MODE`:

| | `lan` (default) | `behind_caddy` |
|---|---|---|
| Reach the panel | `http://<lan-ip>:8080` | `https://$ARGOS_PANEL_DOMAIN/` |
| `:8080` published on host | yes | no (internal only) |
| Cookie `Secure` | off | on |
| HSTS / strict CSP | off | on |
| Browser Push | blocked (no HTTPS) | works |

Switching is a `.env` change + restart. Full matrix in
[Installation](https://cmos486.github.io/argos-edge/getting-started/installation/#panel-access-modes).

## Architecture

Three containers, one docker bridge, one persistent volume per
service. Single Go binary in the panel container with the React
SPA embedded; SQLite as the only datastore. Background
goroutines handle the reconciler / drift detector / job runner /
notifications worker / log ingestor / backup scheduler.

Component diagram + request flow + storage model:
[docs/architecture/](https://cmos486.github.io/argos-edge/architecture/components/).

## Verifying

13 EFFECT-smoke scripts under `scripts/smoke/` cover every
shipped feature end-to-end against a live stack. The
[verification report](https://cmos486.github.io/argos-edge/operations/verification-report/)
maps each feature to its smoke (or documents why no smoke
exists) and is the gate every release passes before tag.

## Documentation

[**docs portal**](https://cmos486.github.io/argos-edge/) — the
full source. Sections:

- [Getting started](https://cmos486.github.io/argos-edge/getting-started/installation/) —
  installation, first run, quickstart.
- [Workflows](https://cmos486.github.io/argos-edge/workflows/) —
  add a host, publish with SSO, respond to an attack, restore
  from backup, onboard an admin, import a cert.
- [Features](https://cmos486.github.io/argos-edge/features/reverse-proxy/) —
  per-feature deep dives (reverse proxy, WAF, AppSec, CrowdSec,
  drift detection, country bans, OIDC, ForwardAuth, manual
  certs, DNS providers, notifications, backups,
  observability).
- [Architecture](https://cmos486.github.io/argos-edge/architecture/components/) —
  components, request flow, storage, threat model.
- [Operations](https://cmos486.github.io/argos-edge/operations/monitoring/) —
  monitoring, tuning, troubleshooting, deployment, release
  process, upgrading, persistence, multi-instance.
- [Reference](https://cmos486.github.io/argos-edge/reference/api/) —
  HTTP API, CLI subcommands, env vars, database schema.

## License

argos-edge is licensed under the
[Business Source License 1.1](LICENSE).

- **Free for**: personal use, non-commercial use, internal
  business use, community contributions, self-hosted
  deployments.
- **Not permitted**: offering argos-edge as a hosted commercial
  reverse proxy, WAF, or application gateway service to third
  parties.
- **Converts to Apache 2.0 on 2030-04-20.**

For commercial licensing inquiries, open an issue or contact
the maintainer.
