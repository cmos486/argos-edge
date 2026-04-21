# Reverse proxy

The core of argos. The panel owns a set of hosts and target groups;
the reconciler turns them into a Caddy config every time a row
changes.

## Three-layer model

```
Host  ->  Target Group  ->  Target[]
```

- A **Host** is one public DNS name + TLS policy + optional Rules +
  optional per-host Security. It references a target group.
- A **Target Group** is a named pool: protocol, health-check policy,
  load-balancing algorithm, TLS-verify policy.
- A **Target** is one upstream endpoint (host:port + weight +
  enabled flag) inside a group.

The indirection is deliberate: several hosts can share one group,
and a group can host one or many targets without the host owning
the knobs that concern the pool (algorithm, health checks).

## Hosts

Fields on a host row:

| Field | Type | Notes |
|---|---|---|
| domain | TEXT UNIQUE | the public FQDN |
| target_group_id | FK | NOT NULL; cannot leave a host without a pool |
| tls_mode | `auto` / `none` / `manual` | `auto` = Let's Encrypt; `none` = plain HTTP; `manual` = operator-uploaded cert (see [Manual certificates](manual-certs.md)) |
| tls_email | TEXT | ACME contact, required when `tls_mode=auto` |
| enabled | bool | disabled hosts return 404 without touching upstream |
| auth_required | bool | flip on for ForwardAuth; see [ForwardAuth](forward-auth.md) |
| tls_challenge | `dns` / `http` / `tls-alpn` | ACME challenge; default `dns`. See [TLS challenges](#tls-challenges) |
| tls_acme_ca_url | TEXT | optional ACME directory override for this host; empty = inherit global. See [ACME CA options](#acme-ca-options) |

TLS-mode `auto` is the right default. Use `none` for internal
hostnames you don't expose to the internet. Use `manual` when you
need to serve a pre-existing cert (private CA, self-signed,
certbot DNS-01 out-of-band); see
[Manual certificates](manual-certs.md) for the full story. A host
with `tls_mode=manual` skips ACME entirely — Caddy serves the
uploaded file and nothing else.

## TLS challenges

`tls_mode=auto` hosts issue certificates from Let's Encrypt (or a
custom ACME CA — see [ACME CA options](#acme-ca-options)). Three
challenge types are supported; pick the one that matches your
network reality.

### DNS-01 (default)

- **Value**: `tls_challenge='dns'`
- **How it works**: Caddy places a `TXT` record via the Cloudflare
  DNS API, Let's Encrypt reads it over recursive DNS.
- **Requires**: `CLOUDFLARE_API_TOKEN` on the caddy container with
  `Zone:DNS:Edit` scope for the domain's zone.
- **Pros**: works behind CGNAT, does not need any inbound port,
  supports wildcard certificates (`*.example.com`).
- **Cons**: locked to Cloudflare today (adding more providers is
  on the roadmap); token needs the right zone scope.

### HTTP-01

- **Value**: `tls_challenge='http'`
- **How it works**: Caddy serves the challenge token on port 80
  at `/.well-known/acme-challenge/<token>`; LE fetches it over
  HTTP.
- **Requires**: port 80 reachable from the Let's Encrypt
  validation servers (any public IP, not a specific one).
- **Pros**: no DNS API token needed; the simplest setup for a
  single public IP.
- **Cons**: **won't work** behind CGNAT, Cloudflare Tunnel, or an
  ISP that blocks inbound :80. **Cannot issue wildcards**.

### TLS-ALPN-01

- **Value**: `tls_challenge='tls-alpn'`
- **How it works**: Caddy answers the challenge over port 443
  using the `acme-tls/1` ALPN protocol on the existing TLS
  listener.
- **Requires**: port 443 reachable from the Let's Encrypt
  validation servers.
- **Pros**: works when port 80 is blocked (rare but happens on
  some residential ISPs).
- **Cons**: **cannot issue wildcards**; same reachability
  constraint as HTTP-01 but on :443.

### Alternative: DNS-01 manual with acme.sh

If your DNS provider is not Cloudflare (or you do not want to give
the panel an API token), issue the cert out-of-band with `acme.sh
--dns` and upload it via Certificates -> Imported. See
[Manual DNS workflow](../tls/manual-dns-workflow.md) for the full
step-by-step. This is the supported path when none of the three
built-in challenges fits; renewals land on the same flow every ~60
days.

### Choosing

| Setup | Recommended challenge |
|---|---|
| Domain on Cloudflare with API token | DNS-01 (default) |
| Single public IP, port 80 open | HTTP-01 |
| Single public IP, port 80 blocked but 443 open | TLS-ALPN-01 |
| Need wildcard cert | DNS-01 only |
| Behind CGNAT / Cloudflare Tunnel | DNS-01 only |
| DNS provider has no API / private setup | [DNS-01 manual with acme.sh](../tls/manual-dns-workflow.md) |

Changes apply on the next reconcile (panel reloads Caddy config on
save). If a wrong challenge was picked, the next renewal attempt
will fail in `caddy_error` logs — see
[Cert troubleshooting](../operations/cert-troubleshooting.md).

## ACME CA options

Every `tls_mode=auto` host asks Caddy to issue a cert through an
ACME v2 directory. By default that directory is **Let's Encrypt
production**. Two knobs let you override this:

- **Global**: `acme.ca_url` setting (empty string = LE production).
  Edit via **Settings → ACME CA**. Presets: production / staging /
  custom URL. Affects every `tls_mode=auto` host that has no
  per-host override.
- **Per-host**: the `tls_acme_ca_url` field (**host form →
  Advanced → ACME CA URL override**). Free-text HTTPS URL; empty
  inherits the global. Use to debug ONE host on LE staging without
  flipping the whole panel.
- **Env var**: `ARGOS_ACME_CA_URL` on the panel container (see
  [env vars](../reference/env-vars.md)) trumps both. Emergency
  escape hatch for ops — forces every `auto` host onto the given
  CA regardless of DB state.

Precedence: `env > per-host > global > "" (LE production)`.

The staging CA (`https://acme-staging-v02.api.letsencrypt.org/directory`)
is there for development. Certs issued from staging chain to an
untrusted root, so browsers will show a warning. Useful when:

- You are iterating on the panel and want to test host creation
  without burning LE production rate limits (50 certs / registered
  domain / week).
- You are debugging an issuance bug on ONE host without affecting
  the rest (set the per-host override, leave the global alone).

Validation: the panel rejects anything that is not a well-formed
`https://` URL with a host. An empty string means "use the
default", not "reject".

See also: [Tuning → ACME CA for development](../operations/tuning.md#acme-ca-for-development).

## Target groups

Fields on a target group:

| Field | Values | Notes |
|---|---|---|
| protocol | `http` / `https` | matches how the upstream is reached |
| verify_tls | bool | only meaningful for `https`; off accepts self-signed |
| algorithm | `round_robin` / `least_conn` / `ip_hash` / `random` | Caddy LB policy |
| health_check_enabled | bool | turns on active health checks |
| health_check_path | TEXT | e.g. `/healthz` |
| health_check_method | `GET` / `HEAD` / `POST` | |
| health_check_expect_status | TEXT | `200`, `200,204`, or `200-299` |
| health_check_interval_seconds | int | 30 default |
| health_check_timeout_seconds | int | 5 default |
| health_check_fails_to_unhealthy | int | 2 default |
| health_check_passes_to_healthy | int | 2 default |

### Multi-target groups

Once you have two or more targets in a group, the LB algorithm
matters:

- `round_robin` — cycle through targets, weighted. Simple, correct
  for stateless backends.
- `least_conn` — pick the target with fewest open upstream
  connections. Right for long-lived requests (streaming, uploads)
  that do not finish at round-robin pace.
- `ip_hash` — same client IP lands on the same target. Use when
  the backend keeps per-client state in memory.
- `random` — pick randomly. Rarely the right answer; mostly present
  for parity with Caddy's LB policies.

Passive health checks (3 fails in a row → 30 s cooldown) are
always on; you layer active checks on top.

### Expect-status

Argos passes `expect_status` to Caddy as typed status codes. Three
forms accepted:

- Single: `200`
- CSV: `200,204`
- Range: `200-299`

Mixed status classes in one field (e.g. `200,400`) are rejected at
the API edge — Caddy's JSON shape drops the status check silently
for cross-class sets, which would weaken the contract.

## Targets

Fields:

| Field | Notes |
|---|---|
| host | IP or DNS name reachable from the argos container |
| port | 1-65535 |
| weight | default 1; used by round_robin + least_conn |
| enabled | disabled targets stay in the group but Caddy skips them |

Weight tuning: values are relative, not percentages. `weight=3` vs
`weight=1` is a 3:1 split, `weight=5` vs `weight=5` is 50/50
regardless of how many other targets exist.

## Rules

Each host has an optional ordered list of **rules** that evaluate in
priority order (low first). The first match wins and is terminal;
unmatched requests fall through to the host's default target group.

Five action types:

| Action | Semantics |
|---|---|
| `forward` | Route to a DIFFERENT target group for this match. |
| `redirect` | HTTP 301/302/307 to another URL. |
| `fixed_response` | Return a canned status + body (no upstream). |
| `block` | Return 403. Use for path or IP blocklists. |
| `rewrite` | Rewrite the request path before forwarding. |

Matchers inside a rule support path (exact, prefix, glob, regex),
header presence / value, method. Multiple matchers AND together
within one rule.

Priority is an integer 1-50000 enforced at the API layer. The DB
used to have a CHECK constraint for this range (migration 006) but
it was removed in migration 007 because the reorder flow needs to
park rows at large temporary priorities during a swap.

!!! note "No rate_limit action type"
    Rate limiting lives on the host itself under Security (per-IP,
    per-header, or global) — not as a rule action. This is a
    deliberate choice to keep Rules a pure routing layer.

## Host-level Security (not reverse-proxy proper, but lives on the Host)

Each host has an optional `host_security` row that configures:

- **WAF** — enabled flag + mode (detect/block) + paranoia 1-4 +
  block status + block body. Reference:
  [WAF](waf.md).
- **Rate limit** — enabled flag + requests + window seconds + key
  (`ip` / `header` / `global`) + header name + status (default
  429).

Rate-limiting and WAF decisions both happen in Caddy before the
reverse_proxy fires.

## How changes reach Caddy

1. Operator edits a row via the panel API.
2. Argos updates SQLite.
3. Argos writes an audit event (who changed what).
4. Argos calls `internal/reconciler.ApplyFromDB()`.
5. Reconciler rebuilds the full Caddy config from DB state and
   POSTs it to `http://caddy:2019/load` (Caddy admin API).
6. Caddy swaps the config in-place, no restart.

Latency from click to live: sub-second in a healthy setup.

## What lives in Caddy vs argos

**Caddy** owns: TLS cert store (`caddy_data` volume), HTTP/3
runtime, connection pooling, inline WAF via Coraza, CrowdSec
bouncer plugin talking to LAPI.

**Argos** owns: the configuration source of truth, the admin UI,
sessions + auth, audit log, notifications, backups, GeoIP, the
reconciler itself.

If Caddy crashes without argos, the last-loaded config persists on
disk and Caddy comes back. If argos crashes without Caddy, the edge
keeps serving on whatever config was last POSTed. Full split:
[Architecture → Components](../architecture/components.md).
