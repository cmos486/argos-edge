# Manual DNS-01 workflow with acme.sh

Issue a Let's Encrypt certificate for a host whose DNS provider has
no native integration in argos-edge, then import the result via
[Manual certificates](../features/manual-certs.md).

This is the supported path when native DNS-01 (Cloudflare via
`tls_challenge='dns'`) is not an option and port 80 / 443 are not
reachable (so HTTP-01 and TLS-ALPN-01 are out too). It is also the
recommended fallback for LAN-only deployments where you do not want
DNS API credentials on the edge.

## When to use this workflow

Pick this when **all** of the following apply:

- Your DNS provider is not Cloudflare, OR you do not want to give
  argos-edge an API token with `Zone:DNS:Edit` on the zone.
- Your host is behind CGNAT, Cloudflare Tunnel, or otherwise not
  reachable from the Let's Encrypt validators on :80 or :443, so
  HTTP-01 / TLS-ALPN-01 are not usable either.
- You still want a public Let's Encrypt cert (i.e. you do not want
  a self-signed cert from an internal CA).

If any of these do NOT apply, prefer the built-in options:

- **Cloudflare DNS-01** — set `tls_challenge='dns'`, configure
  `CLOUDFLARE_API_TOKEN`. See
  [Reverse proxy → TLS challenges](../features/reverse-proxy.md#tls-challenges).
- **HTTP-01 / TLS-ALPN-01** — set `tls_challenge='http'` or
  `tls-alpn` if port 80 or 443 is reachable from the public internet.
- **Private CA** — use [Manual certificates](../features/manual-certs.md)
  directly with a cert issued by your internal CA.

## Prerequisites

- **acme.sh** installed on any machine you trust. Install via the
  upstream instructions at
  [github.com/acmesh-official/acme.sh](https://github.com/acmesh-official/acme.sh).
  The machine does not need to be the panel host; you can run acme.sh
  on your laptop.
- **Access to your DNS provider's control panel** so you can add a
  `TXT` record manually.
- **The domain** under your control (you can observe NS-served TXT
  records with `dig`).

## Step-by-step

### 1. Start the order in acme.sh

```bash
acme.sh --issue --dns -d example.com -d www.example.com \
  --yes-I-know-dns-manual-mode-enough-go-ahead-please
```

The long flag is acme.sh's deliberate "you understand this is manual
and you will be doing the TXT dance yourself" confirmation. It is
required; the command refuses without it.

acme.sh prints something like:

```
Add the following TXT record:
Domain: '_acme-challenge.example.com'
TXT value: 'ABCD1234...random...EFGH5678'

Add the following TXT record:
Domain: '_acme-challenge.www.example.com'
TXT value: 'WXYZ9876...random...IJKL4321'
```

One TXT record per domain/SAN. Wildcards (`-d '*.example.com'`)
work too but the TXT name stays `_acme-challenge.example.com`.

### 2. Add the TXT records at your DNS provider

Log into your registrar or DNS host, add each record exactly as
printed. TTL can be the provider's minimum (often 60 / 300 /
3600 seconds — shorter is better here, you will delete them soon).

### 3. Verify propagation before continuing

Do NOT skip this step. If you tell Let's Encrypt to validate before
the record is live on the authoritative NS, you burn one of your
5-failed-validations-per-hour budget.

Check against a public recursive resolver:

```bash
dig TXT _acme-challenge.example.com +short @8.8.8.8
dig TXT _acme-challenge.example.com +short @1.1.1.1
```

Both should return the exact value acme.sh printed (in quotes).
If they do not, wait for TTL expiry and retry. Some slower providers
take 5-10 minutes; a few take longer.

### 4. Finish the order

```bash
acme.sh --renew -d example.com \
  --yes-I-know-dns-manual-mode-enough-go-ahead-please
```

On success, acme.sh writes the files under
`~/.acme.sh/example.com/` (or `~/.acme.sh/example.com_ecc/` if you
used `--keylength ec-256`):

- `example.com.cer` — leaf certificate.
- `example.com.key` — private key.
- `fullchain.cer` — leaf + intermediates concatenated.
- `ca.cer` — the intermediate chain only.

### 5. Remove the TXT records

Once the cert is issued, the TXT records are no longer needed. Delete
them at your DNS provider. Leaving them live does no harm, but
tidiness matters for next renewal (old values should not linger and
confuse validators that see two TXTs).

### 6. Import into argos-edge

1. Open **Certificates → Imported → Import certificate**.
2. Pick the host from the dropdown.
3. Upload:
    - **Cert**: `example.com.cer` (leaf only) OR `fullchain.cer`
      (leaf + chain together — either works; argos parses both).
    - **Key**: `example.com.key`.
    - **Chain** (optional): if you uploaded just the leaf above,
      upload `ca.cer` here so browsers get the full chain. If you
      uploaded `fullchain.cer`, leave this empty.
4. Click **Import & activate**. The host's `tls_mode` flips to
   `manual` and Caddy reloads with the new cert.

Full UI walkthrough: [Import your own certificate](../workflows/import-own-cert.md).

## Renewal every ~60 days

Let's Encrypt certs are valid for 90 days. Renew before expiry —
60 days before is a comfortable window. argos-edge emits
`manual_cert_expiring_soon` notifications at 30 / 14 / 7 / 1 days
remaining (see [Notifications](../features/notifications.md)), which
is your renewal reminder.

The acme.sh renewal flow is the same as issuance. The TXT values
**change every time** — there is no way to keep the old record valid.
You must do the add-TXT / verify-propagation / confirm dance on each
renewal.

```bash
# Step 1: generate new TXT values
acme.sh --renew -d example.com \
  --yes-I-know-dns-manual-mode-enough-go-ahead-please

# Add the printed TXT records at your DNS provider, verify with dig.

# Step 2: complete the order
acme.sh --renew -d example.com \
  --yes-I-know-dns-manual-mode-enough-go-ahead-please

# Upload the new example.com.cer / example.com.key / ca.cer via
# Certificates -> Imported -> Import certificate (pick the same host;
# the new cert overwrites the old one on activate).
```

The Import dialog warns if the selected host already has a manual
cert ("has manual cert" flag). That is expected during renewal —
importing a new one replaces it atomically. Caddy picks up the new
pair on the next config reload (triggered automatically by the
import).

## Troubleshooting

### "challenge did not pass: authorization must be pending"

acme.sh's internal authorization expired (orders stay pending for
~7 days in Let's Encrypt production). Start a fresh order with
`acme.sh --issue --force` and a new `-d`.

### `dig` returns the old TXT, not the new one

DNS cache. Your provider's authoritative NS may have a longer TTL
than you think. Pick a record TTL of 60-300 seconds next time, and
wait for `2 * TTL` before retrying.

### Cert imports but browsers show "untrusted"

The chain is incomplete. Re-upload with `ca.cer` in the **chain**
field, OR use `fullchain.cer` in the **cert** field and leave
**chain** empty. argos-edge warns at import time if no intermediates
are present AND the leaf is not self-signed.

### Let's Encrypt says "too many failed authorizations"

You hit the rate limit: 5 failed validations per account, per
hostname, per hour. Wait an hour. Before the retry, always verify
the TXT is visible on authoritative NS via `dig` before clicking the
second `--renew`. The propagation check is the single most important
habit for this workflow.

## Future: native integration

A native panel-driven DNS-01 manual flow (Feature 1 of the TLS
roadmap) was considered and deferred in v1.2. The technical analysis
is checked in at
[`docs/internals/dns01-manual-analysis.md`](https://github.com/cmos486/argos-edge/blob/main/docs/internals/dns01-manual-analysis.md)
in the repository. Short version: the acme.sh + Import workflow
covers the use case without adding 3-5 weeks of orchestration code
to the panel. If operator feedback shows the workflow is painful
enough to justify the cost, the feature gets revisited in a later
release.

## Related

- [Manual certificates](../features/manual-certs.md) — feature
  reference for the Import side.
- [Import your own certificate](../workflows/import-own-cert.md) —
  step-by-step UI walkthrough.
- [Reverse proxy → TLS challenges](../features/reverse-proxy.md#tls-challenges)
  — the built-in challenge options you should compare against.
- [Notifications](../features/notifications.md) — how renewal
  reminders get delivered.
