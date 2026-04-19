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

## OIDC SSO + ForwardAuth

Argos supports logging the panel in via any OIDC-compliant provider
(Authentik, Authelia, Keycloak, Google, Okta, ...) AND protecting any
host argos proxies with a ForwardAuth round-trip to the same session.
The local password + TOTP path stays fully working as a break-glass
route when the IdP is unreachable.

### Architecture at a glance

```
browser  ──▶  Caddy (argos-caddy)  ──▶  upstream (huntlo, etc.)
                  │
                  │  [host.auth_required=1]
                  ▼
               forward_auth handler
                  │   GET /api/auth/forward
                  │   cookies forwarded
                  ▼
               argos panel
                  │
                  ├─ cookie valid → 200 + X-Auth-{User,Email,Name,Provider}
                  │                  (copied onto upstream request)
                  │
                  └─ cookie missing → 302 /login?rd=<original_url>
                                      user logs in (password+TOTP or SSO)
                                      cookie Domain=<parent> → subdomains share it
```

Key points:

1. **One provider at a time.** `/system` > SSO holds the issuer URL,
   client id/secret, scopes, email/domain allowlists. The
   `client_secret` is encrypted with the AES-GCM `ARGOS_MASTER_KEY`.
2. **PKCE is mandatory.** Argos never issues a non-PKCE flow.
3. **OIDC users bypass local TOTP** — the IdP is authoritative for
   MFA. Local users keep bcrypt + TOTP exactly as before.
4. **Break-glass:** a local username+password user with TOTP is
   always available. `docker compose exec argos /argos disable-2fa
   --user admin --yes` still resets TOTP if the admin lost both
   phone and recovery codes.
5. **Parent-domain cookie** is what ties the panel session to
   ForwardAuth-protected subdomains. Configure it once, then every
   `*.parent-domain` host argos proxies can be flipped to
   `auth_required=1`.

### Setup: Authentik

1. Providers → Create → OAuth2/OpenID Provider
   - Name: argos
   - Client type: Confidential
   - Redirect URI: `https://argos.example.com/api/auth/oidc/callback`
   - Scopes: openid profile email
2. Applications → Create → bind to the provider.
3. Copy the Client ID + Client Secret.
4. argos **/system** → Single sign-on:
   - Issuer URL: `https://auth.example.com/application/o/argos/`
     (Authentik advertises discovery at
     `<issuer>/.well-known/openid-configuration`; enter only the
     BASE URL).
   - Client ID / Secret: paste.
   - Scopes: `openid email profile`
   - Cookie parent domain: `example.com`
   - Save. Click *Test connection* to confirm discovery.

### Setup: Authelia

1. `configuration.yml` → `identity_providers.oidc.clients`:
   ```yaml
   - id: argos
     secret: "$pbkdf2-sha512$...<hashed secret>"
     redirect_uris:
       - https://argos.example.com/api/auth/oidc/callback
     scopes: [openid, email, profile]
     grant_types: [authorization_code]
     response_types: [code]
     authorization_policy: one_factor
   ```
2. Restart Authelia.
3. argos /system → Single sign-on: issuer `https://auth.example.com`,
   client id `argos`, client secret (plaintext -- Authelia hashes
   it itself), cookie parent `example.com`.

### Setup: Keycloak

1. Create a Realm (or reuse an existing one).
2. Clients → Create client:
   - Client type: OpenID Connect
   - Client ID: argos
   - Client authentication: On
   - Valid redirect URIs: `https://argos.example.com/api/auth/oidc/callback`
3. Credentials tab → copy the Client secret.
4. argos: issuer `https://keycloak.example.com/realms/<your-realm>`,
   client id `argos`, client secret, cookie parent `example.com`.

### Setup: Google OAuth

1. Google Cloud Console → APIs & Services → Credentials →
   Create credentials → OAuth client ID → Web application.
2. Authorized redirect URI:
   `https://argos.example.com/api/auth/oidc/callback`
3. Copy Client ID + secret.
4. argos: issuer `https://accounts.google.com`, client id/secret,
   `scopes: openid email profile`, and CRITICALLY set
   **allowed_domains** to your org domain -- otherwise any Google
   user clicking "Sign in with SSO" would auto-provision.

### Per-host `auth_required` toggle

Hosts → table row → **Auth** column → click the 🔓 / 🔒 badge. The
flag persists, Caddy reconciles in <1s, and every subsequent request
to that host rounds-trips through `/api/auth/forward` before hitting
the upstream. Public hosts are unchanged.

When protected:

- Unauthenticated request → 302 to the panel's `/login` with `rd=`
  pointing back at the original URL.
- Authenticated request → 200 with `X-Auth-User`, `X-Auth-Email`,
  `X-Auth-Name`, `X-Auth-Provider` headers copied onto the upstream
  request (the backend can read them to personalise).

### Known limitations / gotchas

- **Cookie parent domain REQUIRED** for protecting subdomains.
  Without it the session cookie is bound to the panel hostname only,
  so any protected host on a different subdomain sees no cookie and
  stays in a 302 loop.
- **Subdomains only** — every protected host must be a subdomain of
  the configured parent domain. Multi-tenant "two independent parent
  domains in one panel" is out of scope; the cookie spec forbids a
  single cookie covering two siblings.
- **OIDC users bypass local TOTP.** Confirm the IdP enforces MFA
  before enabling OIDC for accounts you care about.
- **A wrong `ARGOS_MASTER_KEY` prevents the panel from booting**
  (the VAPID private key + OIDC client_secret both fail decrypt).
  Rotate by temporarily disabling OIDC, clearing the client_secret,
  updating the env, re-saving the config to re-encrypt.
- **Username collisions:** if a local `alice` exists and a new OIDC
  user's `preferred_username` is also `alice`, argos creates
  `alice-oidc` instead. Further collisions yield a loud error so the
  operator renames manually.

### API surface

- `GET  /api/auth/oidc/available` — public probe `{enabled: bool}`.
- `GET  /api/auth/oidc/login?rd=` — 302 to IdP with PKCE.
- `GET  /api/auth/oidc/callback` — exchange + upsert + session.
- `GET  /api/auth/oidc/status` (authed) — scrubbed config.
- `PUT  /api/auth/oidc/config` (authed) — merge + re-validate.
- `POST /api/auth/oidc/test` (authed) — discovery probe only.
- `GET  /api/auth/forward` — Caddy ForwardAuth endpoint.
- `GET  /api/auth/safe-redirect?rd=` — open-redirect-safe URL.

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md).

## Roadmap

See the phased roadmap in ARCHITECTURE.md. Currently on Phase 0.

## License

MIT
