# Running multiple instances on one host

The shipped `docker-compose.yml` is designed for a single argos-edge
panel per host. Every resource it touches has an explicit name:

- **Containers**: `argos-panel`, `argos-caddy`, `argos-crowdsec`.
- **Volumes**: `argos_panel_data`, `argos_panel_backups`,
  `argos_caddy_data`, `argos_caddy_config`, `argos_caddy_logs`,
  `argos_caddy_manual_certs`, `argos_crowdsec_config`,
  `argos_crowdsec_data`.
- **Network**: `argos_net`.
- **Ports**: `80/tcp`, `443/tcp`, `443/udp`, `8080/tcp`.

Running a second stack on the same host — a staging panel, a
throwaway demo, a CI integration test — requires overriding every
one of those because Compose's project-name flag (`-p <name>`) does
NOT scope explicit `container_name:` or `name:` directives. This
page is the recipe.

!!! note "Why explicit names are the default"
    Fixed names make the panel easy to reason about from outside
    the Compose ecosystem: `docker logs argos-panel`,
    `docker exec argos-panel argos disable-2fa`, monitoring scripts
    that grep `argos-panel` in process lists. The second-instance
    override exists for the cases where that predictability is the
    friction.

## The override pattern

Drop the file below alongside `docker-compose.yml` in the second
clone. Compose picks up `docker-compose.override.yml` automatically
when you pass `-p <project-name>`.

```yaml
# docker-compose.override.yml -- second-instance isolation.
# Rename every container, re-scope every volume + the network,
# remap the published ports.

services:
  crowdsec:
    container_name: argos-demo-crowdsec

  caddy:
    container_name: argos-demo-caddy
    # Skip publishing 80/443 -- the production Caddy already owns
    # them. A demo / staging panel that does not serve real TLS
    # traffic does not need them mapped; argos talks to caddy over
    # the internal bridge. Remove this whole ports key if you need
    # the demo to terminate TLS on different host ports (e.g.,
    # "8081:80", "8444:443").
    ports: !override []

  argos:
    container_name: argos-demo-panel
    # Remap from 8080 (prod) to 8180 (demo). Use !override (not
    # !reset) -- on Compose v2.39+, `ports: !reset []` followed by
    # new items on the same key leaves the list CLEARED, which
    # leaves the port unpublished. !override replaces the list in
    # one shot.
    ports: !override
      - "8180:8080"

volumes:
  caddy_data:         { name: argos_demo_caddy_data }
  caddy_config:       { name: argos_demo_caddy_config }
  caddy_logs:         { name: argos_demo_caddy_logs }
  # caddy_manual_certs introduced in v1.1 (Feature 5 - Import certs).
  # Omitting it here would let the demo and the prod instance SHARE
  # the same operator-uploaded cert files -- silent data clobber.
  caddy_manual_certs: { name: argos_demo_caddy_manual_certs }
  argos_data:         { name: argos_demo_panel_data }
  argos_backups:      { name: argos_demo_panel_backups }
  crowdsec_config:    { name: argos_demo_crowdsec_config }
  crowdsec_data:      { name: argos_demo_crowdsec_data }

networks:
  argos_net:
    name: argos_demo_net
```

Bring the second stack up with an explicit project name:

```bash
docker compose -p argos-demo up -d
```

`-p argos-demo` controls the Compose-internal naming (`docker
compose -p argos-demo ps`, `-p argos-demo down -v`, etc.). The
explicit `container_name:` / `name:` directives above control the
host-level Docker names.

## Fresh `.env` for the second stack

The second stack needs its own secrets. **Do not copy the production
`.env`** — reusing `ARGOS_MASTER_KEY` between two panels means a
leak on either one compromises both, and reusing
`ARGOS_SESSION_SECRET` means sessions cross-validate in confusing
ways.

```bash
cat > .env <<EOF
ARGOS_SESSION_SECRET=$(openssl rand -hex 32)
ARGOS_MASTER_KEY=$(openssl rand -hex 32)
ARGOS_INITIAL_ADMIN_USER=admin
ARGOS_INITIAL_ADMIN_PASSWORD=$(openssl rand -base64 16)
ARGOS_PANEL_MODE=lan
EOF
```

`CLOUDFLARE_API_TOKEN` is optional; only fill if the second stack
will actually use DNS-01 ACME (see
[env vars reference](../reference/env-vars.md)).

## Reach the second panel

With the override above the second panel is at
`http://localhost:8180/` (or wherever the port remap lands). Log
in with whatever `ARGOS_INITIAL_ADMIN_PASSWORD` you set.

## Teardown

```bash
docker compose -p argos-demo down -v
```

`-v` drops the `argos_demo_*` volumes so the second stack
disappears without a trace. Safe because those names never collide
with production (that is the whole point of the override).

## Caveats

- **Image namespace collision.** Both stacks build into the same
  local image tags (`argos-demo-argos`, `argos-caddy:phase1`). A
  second-stack `docker compose build` overwrites the production
  stack's image tag. Either pin different `image:` values in the
  override or accept that the next `docker compose up -d` on the
  production stack will re-tag back to the production build.
- **Caddy ACME rate limits apply per-host, not per-stack.** Two
  stacks that both try to provision the same hostname from Let's
  Encrypt burn the rate limit faster. Use different hostnames.
- **CrowdSec LAPI has its own state.** Two CrowdSec containers on
  the same host means two separate local-decision databases. Each
  bouncer only sees its own stack's decisions.
- **Host-wide ports 80/443.** The override template above skips
  publishing them on the second stack. If you DO need the second
  stack to terminate TLS on a different host port, remap
  (`"8081:80", "8444:443"`) -- but know that Let's Encrypt's
  HTTP-01 ACME challenge only answers on :80, so any
  `tls_mode=auto` host on the second stack will fail to issue
  unless port 80 is reachable from the public internet.

## Related

- [Installation](../getting-started/installation.md) — the default
  single-instance path.
- [Upgrading](upgrading.md) — upgrade one instance at a time; the
  override file stays in place across upgrades.
- [Env vars](../reference/env-vars.md) — what the `.env` values
  mean + which are mandatory.
