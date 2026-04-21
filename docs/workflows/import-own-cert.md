# Import your own certificate

Playbook for putting a pre-existing TLS cert + key in front of an
argos host. Covers three common sources: a private CA, a manually-
issued Let's Encrypt cert (DNS-01 out of band), and a self-signed
cert for LAN hosts.

For the feature reference see [Manual certificates](../features/manual-certs.md).

## Before you start

You need three files (PEM format):

- **`cert.pem`** — the leaf certificate.
- **`key.pem`** — the private key that matches the leaf.
- **`chain.pem`** (optional) — intermediate CAs between your leaf
  and the public root.

The cert must:

- Cover the host's domain (exact match OR wildcard). Wildcards are
  matched per RFC 6125: `*.example.com` covers `www.example.com`
  but NOT `deep.www.example.com`.
- Be valid at upload time (`not_before` in the past, `not_after`
  at least 7 days in the future).

## 1. Make sure the host exists

**Hosts → New host**, fill it out as usual (domain, target group,
TLS email). Leave **TLS mode** at `auto` for now — the import flow
flips it to `manual` automatically. Save the host.

## 2. Open the import dialog

**Certificates → Imported tab → Import certificate**.

The import dialog is its own modal, separate from the host edit
form. (Earlier designs nested the upload form inside the host edit
modal; that caused the Upload button to submit the host form
instead of the upload form. The modal split in v1.1.1 is the fix.)

## 3. Pick the host + upload

In the modal:

1. **Host** dropdown — pick the host you created. Each row shows
   the current `tls_mode` and a flag if the host already has a
   manual cert ("has manual cert").
2. An amber warning appears if the host is currently `tls_mode=auto`,
   confirming the upload will switch it to manual and disable
   auto-renewal.
3. **Certificate** (`cert.pem`) — leaf cert PEM.
4. **Private key** (`key.pem`) — matching key PEM.
5. **Chain / intermediates** (optional) — intermediate CAs. If
   your CA's chain is concatenated into `cert.pem` already, leave
   this blank.
6. Click **Import & activate** (or **Replace & activate** if the
   host already had a manual cert).

Argos validates server-side:

- Cert parses, key parses, they match (`crypto/tls.X509KeyPair`).
- Cert covers the host's domain (`x509.VerifyHostname`; wildcards
  per RFC 6125).
- Cert is valid and not close to expiry (rejected under 7d,
  warned under 30d).
- Chain (if provided) is a series of CERTIFICATE blocks (key blocks
  concatenated by mistake are rejected).

On success the DB row + the host's `tls_mode=manual` flip land in
a single SQL transaction; the PEM files are then written to the
shared `caddy_manual_certs` volume; a Caddy reconcile triggers.

Warnings (non-fatal) appear inline in the modal:

- "cert expires in 14d; consider renewing before upload".
- "no intermediate chain provided; browsers may show 'incomplete
  chain' warnings" — expected for self-signed certs.

## 4. Reconcile runs automatically

The import triggers an argos reconcile. Caddy picks up the
`load_files` entry within a second. No restart.

## 5. Verify

From another machine:

```bash
# Full handshake + cert chain
openssl s_client -connect myapp.example.com:443 -servername myapp.example.com -showcerts < /dev/null
```

The leaf should match what you uploaded. If it doesn't, Caddy
either still has a cached ACME cert (wait a few seconds, or
reload Caddy: `docker compose restart caddy`) or the reconcile
failed — check **Logs → source=caddy_error**.

## 6. Set up an expiry reminder

Manual certs do NOT auto-renew. Wire a notification rule once so
you stop tracking expiries by hand:

**Notifications → Rules → New rule**:

- **Event type**: `manual_cert_expiring_soon`.
- **Channel**: whatever you use (Slack webhook / email / browser
  push).
- **Throttle**: `86400` (one day) — the event fires daily at each
  threshold so throttling is what keeps your inbox sane.

The event fires at 30 / 14 / 7 / 1 days before expiry. Payload
includes the domain, days remaining, threshold crossed, and the
cert fingerprint so you can distinguish reminders across renewals.

## Variant: Let's Encrypt via DNS-01 manual

For domains where you have no Cloudflare API token and port 80 is
blocked (the DNS-01 manual case): issue the cert out-of-band with
`certbot --manual --preferred-challenges dns` or `acme.sh --dns`,
then import via this feature. The panel doesn't ship a built-in
DNS-01 manual client (deferred to v1.2); import is the official
workaround.

Quick `certbot` recipe:

```bash
sudo certbot certonly --manual --preferred-challenges dns \
    -d 'myapp.example.com' \
    --agree-tos -m you@example.com
# Follow prompts: add TXT record, wait for propagation, press enter.

# Certbot writes to /etc/letsencrypt/live/myapp.example.com/
ls /etc/letsencrypt/live/myapp.example.com/
# cert.pem  chain.pem  fullchain.pem  privkey.pem
```

Upload `cert.pem` as the certificate, `privkey.pem` as the key,
and `chain.pem` as the chain. Or use `fullchain.pem` as the
certificate and leave chain blank — the validator handles both.

## Variant: self-signed for a LAN host

For an internal hostname where "untrusted cert" is acceptable as
long as the connection is encrypted:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -nodes -days 365 -subj '/CN=intranet.lan' \
    -addext 'subjectAltName=DNS:intranet.lan' \
    -keyout key.pem -out cert.pem
```

Upload `cert.pem` and `key.pem`; leave chain blank. The validator
emits a warning about the missing chain (expected for self-signed)
but the cert activates.

Browsers will still show a warning because your cert does not
chain to a trusted root. Distribute `cert.pem` as a trusted CA
on your internal devices (or use a private CA like Step-CA /
Smallstep) to make the warning go away.

## Rotating / replacing

Open **Certificates → Imported → Import certificate** and pick the
same host. The dropdown labels it "has manual cert"; the submit
button changes to **Replace & activate**. The panel prompts to
confirm replacement. The old key is overwritten atomically (tmp
file + rename) so Caddy never sees a half-updated pair.

## Removing

**Certificates → Imported tab → Remove** on the row.

Both:

1. Delete the files from the shared volume.
2. Delete the DB row.
3. Revert the host to `tls_mode=auto` by default. Pass
   `?revert=none` if you want to serve plain HTTP instead.

## Related

- [Manual certificates](../features/manual-certs.md) — feature
  reference.
- [Cert troubleshooting](../operations/cert-troubleshooting.md)
  — when to use manual vs fix an ACME issue.
- [Notifications](../features/notifications.md) — event catalog
  and rule setup.
