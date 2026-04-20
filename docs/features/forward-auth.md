# ForwardAuth

ForwardAuth lets you put *any* backend behind the same session
cookie the panel issues. Caddy asks argos on every request, argos
answers `200 OK` with identity headers or `302 /login`, the
upstream only sees requests that already have a valid session.

## Enabling

Two conditions:

1. The host has `auth_required=1` (toggle in **Hosts → *your host*
   → Auth required**).
2. The panel's **Cookie parent domain** covers both the panel host
   AND the target host. Example: panel is `panel.example.com`,
   target is `myapp.example.com`, parent must be `example.com`.

Argos does not issue ForwardAuth cookies that would fail on the
target domain; setting the parent is operator responsibility.

## Request path

```
Client  ->  Caddy (myapp.example.com:443)
           CrowdSec bouncer check (external bans)
           AppSec / WAF
           forward_auth handler  ->  argos:/api/auth/forward
                              <-  200 + X-Auth-* headers
                                 OR  302 /login?rd=...
           reverse_proxy  ->  upstream
```

The ForwardAuth sub-request forwards the original method, URI,
Host, and cookies to argos. Argos' handler:

- Reads the `argos_session` cookie.
- Looks up the session in SQLite (with an in-process 30 s cache
  keyed by token).
- On success: sets `X-Auth-{User,Email,Name,Provider}` headers
  that Caddy copies onto the upstream request. Returns 200.
- On failure: reconstructs the original URL from
  `X-Forwarded-{Proto,Host,Uri}` and redirects the browser to the
  panel's `/login?rd=<escaped-url>`. The return-to validator
  ensures the panel only redirects to hosts within the cookie
  parent domain subtree.

## Cookie shape

With a parent domain set:

- `Domain=.example.com` — cookie visible to every host under the
  parent, so ForwardAuth on `myapp.example.com` sees the cookie
  issued by `panel.example.com`.
- `SameSite=Lax` — necessary because the OIDC callback and the
  ForwardAuth-triggered redirect both involve a cross-subdomain
  navigation that `Strict` would drop the cookie on.
- `HttpOnly` + `Secure` (in `behind_caddy` mode) still enforced.

Without a parent domain:

- No `Domain` attribute — cookie is host-scoped to the panel only.
- `SameSite=Strict`.
- ForwardAuth on any OTHER host sees no cookie -> always 302s to
  login. **Do not enable auth_required when the parent is unset.**

## Cache behaviour

The panel holds a per-token cache of ForwardAuth lookups with a
30-second TTL:

- Hit: return cached 200 + headers. No SQL round-trip.
- Miss or stale: re-fetch session + user from SQLite, emit a
  `session.Touch` so idle-timeout stays accurate, cache the new
  entry.
- Logout: `session.Delete` + `ForwardAuthCache.Invalidate(token)`
  eagerly evict the entry so the very next request on a protected
  host bounces to /login without waiting the 30 s.

The cache is in-process; a panel restart rebuilds it on first
request per session.

## What the upstream sees

Four headers added to the proxied request:

| Header | Value |
|---|---|
| `X-Auth-User` | Username (the `users.username` row). |
| `X-Auth-Email` | `users.email`, set when available. |
| `X-Auth-Name` | Display name (OIDC `name` claim or none for locals). |
| `X-Auth-Provider` | `local` or `oidc`. |

The upstream can use these to skip its own login screen. Typical
pattern with a backend that supports trusted header auth
(Grafana, Nextcloud, Gitea, ...):

```yaml
# Grafana example env
GF_AUTH_PROXY_ENABLED: "true"
GF_AUTH_PROXY_HEADER_NAME: "X-Auth-User"
GF_AUTH_PROXY_HEADERS: "Email:X-Auth-Email Name:X-Auth-Name"
GF_AUTH_PROXY_AUTO_SIGN_UP: "true"
GF_AUTH_PROXY_WHITELIST: "10.0.0.0/8"  # or the Caddy docker IP
```

!!! warning "Do not trust X-Auth-* when the upstream is directly reachable"
    The headers are only trustworthy when the request came through
    Caddy. If the upstream is bound to `0.0.0.0` and anyone on the
    LAN can reach it directly, an attacker can inject arbitrary
    `X-Auth-*` values and bypass auth entirely. Mitigations:
    bind to the docker bridge only, or have the upstream check a
    shared-secret header that Caddy adds in addition.

## Panel mode interaction

ForwardAuth works in both `lan` and `behind_caddy` panel modes. In
`behind_caddy`:

- Caddy is the only entry point; cookies are `Secure`.
- The ForwardAuth sub-request from Caddy to `argos:8080` travels
  inside the docker bridge network.

In `lan`:

- The panel port is published; argos is also reachable directly.
- Cookies are NOT `Secure` (panel is on plain HTTP).
- ForwardAuth *still works* for protected hosts served over HTTPS
  by Caddy — the cookie travels over HTTPS on those requests. But
  the panel itself is on HTTP, so the cookie is exposed on the LAN
  for anyone sniffing panel traffic. Reconsider `behind_caddy` if
  you need the strong cookie posture.

## Failure modes

- **302 loop**: the return-to URL validates as unsafe and bounces
  back to `/login`. Usually caused by the target host being outside
  the cookie parent domain subtree, or by the request carrying a
  malformed `rd=` parameter. Look at the panel's audit log for
  `oidc_login_failed` with stage=`state_not_found` or the
  reconstructed URL.
- **Headers missing upstream**: Caddy received 200 but the upstream
  does not see the headers. Confirm Caddy's forward_auth directive
  has `copy_headers X-Auth-User X-Auth-Email X-Auth-Name
  X-Auth-Provider` (argos' reconciler emits this — a hand-edited
  Caddyfile might not).
- **Upstream shows wrong user**: the ForwardAuth cache can hold a
  recently-logged-out session for up to 30 s on hosts OTHER than
  the one the logout hit, because Logout only evicts the cache of
  the argos instance that served it. Single-panel deployments see
  this window; multi-panel are not supported.

## Related

- [Publish with SSO](../workflows/publish-with-sso.md) — enable
  ForwardAuth on a host.
- [OIDC SSO](auth-oidc.md) — how the initial session is minted.
- [Reverse proxy](reverse-proxy.md) — the full Caddy pipeline.
