# Certificate troubleshooting

Triage recipe when a cert is not issuing, not renewing, or expiring
without anyone noticing.

Most cert problems are visible in two surfaces:

- **`/certs`** — the enriched table. One row per
  `tls_mode=auto` host; shows status (ok / warning / critical /
  expired / unknown), days-left, last renewal event (with a dot that
  is green on success, red on failure), next-renewal estimate, and a
  **Renew now** button.
- **`/logs?source=caddy_error`** — Caddy's error log with ACME
  diagnostics. Deep-link from each cert row via the **Logs** button.

## Reading the status column

| Status | Meaning |
|---|---|
| `ok` | more than 30 days remaining; Caddy will renew at ~30d automatically |
| `warning` | 7-30 days remaining; renewal should fire soon |
| `critical` | < 7 days remaining; renewal should already be firing |
| `expired` | past `not_after`; browsers will reject the cert |
| `unknown` | the panel could not dial Caddy on :443 for this SNI. Usually means the cert has not been issued yet (fresh host, DNS not propagated) or Caddy is down |

`unknown` on a brand-new host is expected: it clears the moment
Caddy completes the first ACME order. `unknown` on an established
host is a problem — investigate.

## The Last event column

Each row shows the most recent `caddy_error` row mentioning the
domain. Green dot = success, red dot = failure; the tooltip carries
the full message, the timestamp links to the filtered log view.

A red dot + a non-ok status is the signal. A red dot on a cert
that is still `ok` usually means an older failed attempt that
Caddy later recovered from — no action needed.

## Renew now

The **Renew now** button POSTs to `/api/certs/{host_id}/renew`,
which asks argos's reconciler to re-push the current config to
Caddy. Caddy's certmagic then re-evaluates every policy:

- Certs inside the renewal window (< ~30 days left) are renewed.
- Certs outside the window are a no-op — the button does NOT force
  a fresh issuance for a cert that is comfortably valid. This is
  intentional: Let's Encrypt rate limits are production-tight
  (50 certs per registered domain per week) and a
  guaranteed-force-now button would trivially burn them.

The UI labels this correctly: the toast says "renewal check
queued", not "renewed". If you genuinely need to force re-issuance
(testing a new challenge, recovering from a corrupted account),
the options are:

- Flip `tls_mode` from `auto` to `none`, save, flip back. Caddy
  drops the automation entry and recreates it, which does force a
  fresh order. **Caveat**: during the `none` window the host
  serves plain HTTP, so users see a reset TLS handshake.
- Use Let's Encrypt staging (**Settings → ACME CA → Staging** or
  per-host override) so rate limits are ~30× higher while you
  debug.

## Common failure modes

### "connection refused" on port 80 (HTTP-01)

Cert event message contains `dial tcp ...:80: connect: connection
refused` or similar. Means:

- Your router / firewall is not forwarding :80 to the argos host.
- Upstream ISP blocks inbound :80 (common on residential US ISPs).

Fix: switch the host's `tls_challenge` to `dns` (if you have a
Cloudflare zone) or `tls-alpn` (if :443 is open but :80 is not).

### "connection refused" on port 443 (TLS-ALPN-01)

Same as above but for :443. If even :443 is blocked, only DNS-01
will work.

### "no valid A/AAAA records" (any challenge)

DNS hasn't propagated yet, or the record points to the wrong IP.
`dig +short <your.domain>` should return the public IP of the
argos host. Wait for the TTL to expire, then retry.

### "Forbidden: 403 ... invalid API token" (DNS-01)

`CLOUDFLARE_API_TOKEN` is missing, wrong, or scoped to the wrong
zone. The panel validates at host-save time when the challenge is
`dns` to catch this early — but if the token was right at save and
later rotated, issuance fails. Rotate the token and `docker compose
restart caddy`.

### "too many certificates already issued" (rate limit)

You hit the Let's Encrypt production rate limit (50 certs per
registered domain per week). This is usually caused by a loop:
renewals failing fast, then a script retrying. Two moves:

1. **Stop the loop.** Disable the offending host (`Hosts → toggle
   off`) until you understand why it is churning.
2. **Switch to staging** until the 7-day window passes: **Settings
   → ACME CA → Staging** (panel-wide) or use the per-host override
   for just this domain. Staging issues untrusted certs (browser
   warning) but has a 30k/week limit.

See [Tuning → ACME CA for development](tuning.md#acme-ca-for-development).

### "cannot issue wildcard certificate" (HTTP-01 / TLS-ALPN-01)

Wildcard SAN (`*.example.com`) only works with DNS-01. The panel
doesn't currently accept wildcard domains in the create form (the
validator rejects them) but some imports or API pushes can land
with wildcards. Switch the host to `tls_challenge=dns`.

### "expired" status but Caddy is running

Usually means renewal has been failing silently for weeks. Open the
**Logs** link from the cert row, filter to `source=caddy_error
AND q=<domain>`, and read the most recent failures. The root cause
is almost always one of the above four.

Once fixed, **Renew now** picks up the cert immediately (it is
inside the renewal window by definition).

## What "Renew now" cannot do

- Force renewal of a cert that is comfortably valid (>30d). The
  button is a re-check, not a bypass of Caddy's renewal window.
- Switch CAs on the fly — for that, edit **Settings → ACME CA**
  or the per-host override and save; the next reconcile uses the
  new directory URL.
- Bypass rate limits. If you are already limited, clicking faster
  makes it worse.

## Related

- [TLS challenges](../features/reverse-proxy.md#tls-challenges) — choosing a challenge.
- [ACME CA options](../features/reverse-proxy.md#acme-ca-options) — switching between production and staging.
- [Tuning → ACME CA for development](tuning.md#acme-ca-for-development) — why staging exists.
- [env vars → CLOUDFLARE_API_TOKEN](../reference/env-vars.md#cloudflare_api_token) — DNS-01 auth.
- [env vars → ARGOS_ACME_CA_URL](../reference/env-vars.md#argos_acme_ca_url) — ops-level CA override.
