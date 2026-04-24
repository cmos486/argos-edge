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
`crowdsecurity/appsec-default` + `argos/appsec-detect` collections
and copies the acquisition files into the persistent config
volume. Subsequent container restarts load the collections from
`/etc/crowdsec/` directly — the script runs once per fresh install.

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
- [WAF](waf.md) — rule exclusions, custom SecRules, paranoia levels,
  per-host opt-in, AppSec metrics dashboard.
- [Notifications](notifications.md) — the catalog of event types
  including `appsec_unavailable`.
- [Troubleshooting — AppSec](../operations/troubleshooting.md) —
  specific symptom-to-diagnosis mappings.
