# Overview

Argos-edge is a single-binary panel that operates a Caddy reverse
proxy, a Coraza/CRS WAF, and a CrowdSec bouncer on top of a SQLite
datastore. Everything — hosts, TLS certificates, WAF modes, auth
policy, notifications, backups — is configured from a browser and
applied live via Caddy's admin API.

The project targets homelabs. It is not a hyperscaler load balancer,
it is not a Kubernetes ingress, and it does not try to. What it does
aim for is: one person, one LXC/VM, several services, sane defaults,
visible enough when something breaks.

## The two deployment shapes

Argos ships with two compose modes selected via `ARGOS_PANEL_MODE`:

- **`lan`** (default): the panel binds on `0.0.0.0:8080` and is
  reached at `http://<host-ip>:8080`. No TLS, cookie `Secure` flag
  off, HSTS not sent. Intended for a trusted LAN where the panel
  itself is not internet-exposed. Hosts managed by argos still get
  Let's Encrypt certs through Caddy; only the panel is plaintext.
- **`behind_caddy`**: the panel port is *not* published on the host,
  and Caddy reverse-proxies `https://$ARGOS_PANEL_DOMAIN/` to
  `argos:8080` on the internal docker bridge. Cookie `Secure` on,
  `SameSite=Strict`, HSTS + CSP enabled. This is the shape for
  internet exposure.

Switching modes is a `.env` change + restart. The full matrix is in
[Installation](getting-started/installation.md#panel-access-modes).

## What runs inside

Three containers defined in `docker-compose.yml`:

1. **`caddy`** — Caddy 2 with the CrowdSec bouncer plugin and Coraza
   compiled in. Handles TLS termination, HTTP/3, reverse proxy,
   health checks, inline WAF, and CrowdSec-driven blocklisting.
2. **`crowdsec`** — the CrowdSec LAPI daemon plus the AppSec
   component. Reads Caddy access logs, runs scenarios, pushes
   decisions that the bouncer enforces. AppSec is the runtime that
   executes OWASP CRS against each request.
3. **`argos`** — the Go panel. Exposes the HTTP API + bundled SPA,
   owns the SQLite DB, drives Caddy through its admin API, mints
   sessions, runs the notification worker + backup scheduler + GeoIP
   refresh + retention cron.

A `behind_caddy` deploy adds an override that drops the `argos:8080`
port publication so only Caddy reaches the panel.

## Data lives in SQLite

Everything that the operator configures lives in a single SQLite file
at `/data/argos.db` inside the `argos` container. Tables cover users,
sessions, hosts, target groups/targets, rules, WAF exclusions + custom
rules, host security policy, notifications (channels/rules/deliveries/
push subscriptions), backups metadata, log entries, and settings. WAL
mode with NORMAL fsync; single-writer.

The frontend is embedded into the Go binary via `go:embed`, so there
is nothing for the operator to run alongside.

## Configuration surface

Environment variables cover the **bootstrap and security posture**:
session secret, master key for AES-GCM at-rest encryption, initial
admin, panel mode, log paths. Full reference:
[Env vars](reference/env-vars.md).

Runtime settings (retention windows, cron schedules, OIDC client,
etc.) live inside the panel's settings table and are editable from
System → Settings. They survive restarts and are captured in backups.

## How a request flows

At the coarsest level:

```
client  ->  Caddy (:443)  ->  [CrowdSec bouncer pre-check]
                           ->  [AppSec / WAF]
                           ->  [optional: ForwardAuth to argos]
                           ->  reverse_proxy to upstream
```

Details, including the OIDC handshake and the ForwardAuth cookie
semantics, live in [Request flow](architecture/request-flow.md).

## What this project is not

- **Not a Kubernetes ingress.** It owns one Caddy instance, not a
  fleet.
- **Not multi-tenant.** Every operator with a panel login sees every
  host. There are no roles.
- **Not HA.** SQLite, no clustering, no leader election. If the
  container restarts, existing sessions survive (DB-backed); in-flight
  OIDC login state is invalidated by design.
- **Not a CDN or cache.** Caddy's basic cache is available via the
  Caddyfile but argos does not configure it; operators extend by
  hand.

If any of those is a blocker, argos is the wrong tool.

## How to read the rest of this site

- **[Getting started](getting-started/installation.md)** first — it
  leaves you with a running panel and your first host on Let's
  Encrypt.
- **[Workflows](workflows/index.md)** for the top half of the
  operator's weekly work: adding a host, bringing a service under
  SSO, reacting to an attack.
- **[Features](features/reverse-proxy.md)** when you want to
  understand one subsystem in depth.
- **[Architecture](architecture/components.md)** when you want the
  map before the territory.
- **[Reference](reference/env-vars.md)** for flat lookup of env vars,
  API endpoints, CLI subcommands, and table shapes.
