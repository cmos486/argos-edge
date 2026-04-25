# Access control (geo-blocking, IP allowlists)

Operators migrating from Zoraxy / NPM / Traefik often look for an
equivalent of "country blacklist" or "LAN-only access" in argos.
The argos panel does not surface either as a first-class UI knob,
but the bundled CrowdSec sidecar already implements both. This
page documents the recipes.

## Country-based blocking (geo-blocking)

**Use case:** drop all traffic from specific countries (typical
homelab list: jurisdictions where the operator has no users)
without writing iptables rules or maintaining a separate firewall
config.

**Mechanism.** CrowdSec ships a GeoLite2 database in-container; no
extra collection install needed. `cscli decisions add` accepts
`--scope Country` and the bouncer inside Caddy looks up the
client IP per request, blocking matches before the request reaches
any handler.

!!! warning "v1.3.21+ required for actual enforcement"

    Country blocking via raw `cscli decisions add --scope
    Country` does NOT enforce at the Caddy edge in any
    argos release. The upstream `hslatman/caddy-crowdsec-
    bouncer` plugin lacks `scope=Country` support entirely
    (verified Apr 25 2026 against plugin commit `f1e77b2`).

    **v1.3.21** ships the fix: the panel expands country
    bans into the equivalent list of `scope=Range`
    decisions, which the plugin handles natively. Use the
    new endpoints below; do NOT rely on raw cscli for
    country-scope work.

    Pre-v1.3.21 stacks should treat the country-blocking
    path as broken and upgrade. See
    [release notes for v1.3.20](../release-notes/v1.3.20.md)
    for the upstream-source citation if you need to
    explain the gap to an external auditor.

### How v1.3.21 expansion works

When the operator bans a country, the panel:

1. Looks up the CIDR list for that country in the embedded
   GeoIP MMDB (DB-IP Lite, refreshed monthly via the same
   cron that powers IP enrichment).
2. Pushes one `--scope Range --type ban` decision to LAPI
   per CIDR, tagged with origin `argos-country-XX`.
3. Persists a tracking row in the `country_ban_expansions`
   table mapping the country code to the CIDR list and the
   MMDB version at creation time.

Revocation reverses (1)-(3) in one HTTP call:
`DELETE /v1/decisions?origins=argos-country-XX` clears every
expansion-emitted decision atomically.

A small country (Andorra, Vatican) expands to a few CIDRs;
a large country (CN, US, RU, IN) expands to 500-1500. The
bouncer's radix tree handles the count without measurable
overhead.

### Endpoints

```
POST   /api/security/countries/expand
       body: {"country_code":"BR","duration":"168h","reason":"..."}
       -> 201 + { country_code, cidr_count, mmdb_version, ... }

GET    /api/security/countries
       -> [ { country_code, cidrs, cidr_count, ... }, ... ]

DELETE /api/security/countries/{cc}
       -> 200 + { country_code, removed_decision_count }
```

The Settings page surfaces a minimum-viable UI (table +
add-form + revoke button). Richer UI (flag picker,
heatmap) is queued for v1.3.22.

### Verification

```bash
TEST_COUNTRY=<ISO> TEST_IP=<ip-resolving-to-iso> \
  TEST_HOST=https://<your-host> \
  ./scripts/smoke/country-block.sh
```

Exit 0 (HTTP 403) on v1.3.21 stacks AFTER the operator has
converted the test country via the expand endpoint above.
Exit 1 (any non-403) on every pre-v1.3.21 stack -- the
script is the regression test for the bug v1.3.21 fixes.

**Add a country block:**

```bash
docker exec <crowdsec-container> cscli decisions add \
  --scope Country \
  --value <ISO>          \
  --duration <duration>  \
  --reason "<reason>"    \
  --type ban
```

Where:

- `<ISO>` is an ISO 3166-1 alpha-2 country code (`XX`, `YY`,
  `ZZ`, ...). Examples in the wild: `XX` for one nation,
  `YY` for another, `ZZ` for a third. Substitute the
  jurisdictions you want to block based on your own threat
  model.
- `<duration>` accepts Go duration syntax: `24h`, `168h` (one
  week), `8760h` (one year). For a permanent block use a
  large value such as `876000h` (100 years) -- CrowdSec has
  no `forever` literal.
- `<reason>` is free-form audit text. It surfaces in
  `cscli decisions list` and in the panel Threats tab.

**List active country decisions:**

```bash
docker exec <crowdsec-container> cscli decisions list --scope Country
```

**Remove a decision:**

```bash
docker exec <crowdsec-container> cscli decisions delete --id <ID>
```

**Propagation.** The bouncer inside argos's Caddy polls CrowdSec
LAPI on the cadence set by the `crowdsec.ticker_interval` field
emitted into the Caddy config (default `15s` in the shipped
docker-compose). Add or remove a decision and the next request
from a matching IP either gets blocked or unblocked within that
window. No Caddy reload, no panel restart.

**Audit trail.** Every block surfaces in the panel's Threats tab
under the country code with the reason field intact. Decisions
created via cscli show as origin `cscli`; decisions created from
the panel UI (manual ban from the Threats tab) show as origin
`crowdsec`.

## IP allowlist (LAN-only access)

**Use case:** a host is exposed via DNS + valid TLS but should
only be reachable from internal IPs (LAN, VPN, jump box). Common
for admin panels, dashboards, internal tooling.

Three approaches, in order of recommendation:

### Approach A (recommended, v1.3.18+): native argos LAN-only toggle

argos ships a per-host **LAN-only** checkbox in the Edit Host
modal. When enabled, the panel emits a Caddy gate route that
matches every PUBLIC source IP and serves a `403 Access denied`
terminally; LAN, VPN, and loopback clients fall through to the
normal request chain.

Allowed source ranges:

```
127.0.0.0/8     loopback
::1/128         loopback (IPv6)
10.0.0.0/8      RFC 1918
172.16.0.0/12   RFC 1918
192.168.0.0/16  RFC 1918
fc00::/7        ULA (IPv6)
```

**How to enable:** Hosts page → click the host → Edit modal →
Access section → check "LAN-only access (block requests from
public IPs)" → Save. Reconcile is automatic; no panel restart.

**Visual indicator:** the Hosts list shows an amber `LAN` badge
next to the domain when the toggle is on, so you can spot which
hosts are private at a glance.

**Caveat: trusted_proxies.** Caddy's remote_ip match operates
on whatever client IP Caddy resolved -- which depends on the
`trusted_proxies` config. argos sets sensible defaults for
the standard private ranges (v1.3.8) so an `X-Forwarded-For`
chain from a private hop resolves correctly. **If argos is
behind another reverse proxy / CDN whose egress IP is NOT in
the standard private ranges**, that proxy IP gets seen as the
"client" and the gate doesn't fire. In that shape:

- Add the upstream proxy's IP/range to argos's
  `trusted_proxies` in the Caddy `main` config (currently
  done via `backend/internal/caddycfg`).
- Or apply Approach B at the upstream proxy.

For the typical homelab shape (argos directly exposed on the
WAN, public DNS resolves to argos's IP), no extra config is
needed -- the toggle works out of the box.

### Approach B: firewall at the router

Block WAN -> LAN at the gateway for the specific TCP port (or
the specific public IP that resolves to the host) so external
clients never reach Caddy at all. argos itself stays unaware.

Pros: cleanest separation -- argos is a pure reverse-proxy /
WAF / SSO layer and access policy lives in the firewall.
Removes argos as a single point of failure for the access-
control rule. Useful when argos itself shouldn't enforce the
restriction (e.g. defense in depth, or argos sits behind a
shared reverse proxy you don't fully control).

Cons: requires a router with firewall rule support
(OPNsense, OpenWrt, UDM-Pro, pfSense, ...). A consumer ISP
gateway that only exposes port-forward toggles can't express
"public IP X is forwarded but only when source is LAN", since
NAT happens after forward decisions.

### Approach C: CrowdSec range whitelist via custom scenario

Possible but requires writing a CrowdSec scenario that emits
ban decisions for any source NOT in `192.0.2.0/24`-style RFC
1918 ranges. The recipe is non-trivial and CrowdSec's
acquisition pipeline is the wrong layer for "block by
default". Not recommended unless A and B are both unavailable
in your stack.

## How access control interacts with AppSec

Geo-blocking and AppSec stack cleanly. The bouncer decision check
runs **before** the AppSec request is built:

```
client -> Caddy -> [crowdsec bouncer: in active decision list?]
                        |
                  ban -> 403 returned, AppSec never invoked
                        |
                  pass -> [AppSec inline check]
                        |
                                 -> reverse_proxy to upstream
```

A request from a country in the blocklist gets rejected at the
first stage; AppSec rules don't run, and the panel's AppSec
metrics never count it. The panel's Threats tab is the audit
surface for blocked-by-bouncer events; the AppSec page is the
audit surface for rule-matched events that passed the bouncer.

This stacking is a feature: it keeps AppSec budget (CPU,
memory, alert volume) focused on requests from non-blocklisted
sources rather than burning it on traffic that was never going
to reach a backend.

## Migration cheat-sheet from other reverse proxies

| Other-proxy feature | argos equivalent |
|---|---|
| Zoraxy "Country filter" / NPM blocklist | `cscli decisions add --scope Country --value <ISO>` |
| Zoraxy / NPM single-IP blacklist | `cscli decisions add --scope Ip --value <IP>` |
| Range / CIDR blacklist | `cscli decisions add --scope Range --value <CIDR>` |
| Country **whitelist** (only allow X, Y) | No direct equivalent. Workaround: enumerate every other ISO code as a ban (~250 decisions). Better: use a VPN-only access pattern + firewall. |
| IP **whitelist** (LAN-only) | Approach A / B / C above |
| User-Agent block | CrowdSec `crowdsecurity/http-bad-user-agent` scenario, already in the shipped collection set |
| Path-based deny rules | Per-host security rules in the panel (Hosts -> Security tab) |

## Verifying

After adding a country decision, test from a known source IP
in the target country. From a host whose public IP resolves to
that country (commercial VPN with regional exit, mobile
hotspot when traveling, ...) the request returns 403:

```bash
# From inside the country (example):
$ curl -i https://yourhost.example.com/
HTTP/2 403
```

`cscli decisions list --scope Country` shows the decision is
still active. `docker compose logs caddy --since 1m | grep
'crowdsec'` shows the block event.

If a request from inside the country returns 200 / 304 instead
of 403, check the panel's Settings -> "Country bans (expanded)"
section: the country must appear there with a non-zero CIDR
count. If it does not, the operator has only the legacy raw
cscli decision (which does not enforce) and needs to convert
via `POST /api/security/countries/expand` (or use the panel
Add form). Run `scripts/smoke/country-block.sh` to confirm.

## Removing a country block

```bash
docker exec <crowdsec-container> cscli decisions delete \
  --scope Country --value <ISO>
```

Or by id (use `cscli decisions list` to find it). Same 15s
propagation window as adding.

## Related

- [CrowdSec feature page](../features/crowdsec.md) -- the LAPI
  bouncer fundamentals: how decisions reach Caddy, where the
  GeoLite2 DB lives, how the panel Threats tab visualises
  active bans.
- [AppSec feature page](../features/appsec.md) -- where in the
  request pipeline the bouncer check sits relative to the WAF
  rules.
- [Troubleshooting](troubleshooting.md) -- "Why is my host
  reachable from the internet?" for the IP allowlist case.
