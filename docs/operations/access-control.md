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

**argos has no native UI toggle for this.** Three approaches in
order of recommendation:

### Approach A (recommended): firewall at the router

Block WAN -> LAN at the gateway for the specific TCP port (or
the specific public IP that resolves to the host) so external
clients never reach Caddy at all. argos itself stays unaware.

Pros: cleanest separation -- argos is a pure reverse-proxy /
WAF / SSO layer and access policy lives in the firewall.
Removes argos as a single point of failure for the access-
control rule.

Cons: requires a router with firewall rule support
(OPNsense, OpenWrt, UDM-Pro, pfSense, ...). A consumer ISP
gateway that only exposes port-forward toggles can't express
"public IP X is forwarded but only when source is LAN", since
NAT happens after forward decisions.

### Approach B: CrowdSec range whitelist via custom scenario

Possible but requires writing a CrowdSec scenario that emits
ban decisions for any source NOT in `192.0.2.0/24`-style RFC
1918 ranges. The recipe is non-trivial and CrowdSec's
acquisition pipeline is the wrong layer for "block by
default". Not recommended unless approach A is unavailable
and approach C is too far out.

### Approach C: wait for native argos LAN-only toggle (roadmap)

A per-host "LAN-only access" checkbox is on the open issue
list. Implementation is straightforward: emit a Caddy
`@lan` matcher with `remote_ip` against the RFC 1918 ranges
plus loopback, and reject anything else with a 403.

This release does NOT ship the toggle; this section will be
updated once it does.

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
