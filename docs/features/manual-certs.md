# Manual certificates

Upload your own TLS certificate + private key for a host. Caddy
serves it directly; no ACME issuance, no automatic renewal. Added
in v1.1 as Feature 5 of the cert-lifecycle roadmap.

## When to use it

`tls_mode=auto` (ACME) is the right default for 95% of setups.
Reach for `tls_mode=manual` only when:

- The host is on an internal / private CA your organisation runs
  (Smallstep, Step-CA, HashiCorp Vault PKI, etc.). ACME would not
  chain to a trusted root for your users; manual serves the right
  cert.
- The host is LAN-only and you use a self-signed cert plus a
  private trust store rolled out to internal devices.
- You have a pre-purchased commercial cert you must use (EV cert
  from a CA that is not Let's Encrypt, free cert bundled with a
  domain registrar).
- You need **DNS-01 manual** (see the v1.1 [ACME analysis](../release-notes/v1.0.1.md)):
  issue the cert out-of-band with `certbot --manual` or
  `acme.sh --dns`, then import via this feature.

If you are uploading a Let's Encrypt cert obtained via `certbot`
just to avoid wiring CLOUDFLARE_API_TOKEN — don't. Use `tls_challenge=http`
instead (see [Reverse proxy → TLS challenges](reverse-proxy.md#tls-challenges));
that keeps auto-renewal working.

## How it works

```
  browser -- TLS handshake --> caddy
                                |
                                v
        /etc/caddy/manual-certs/<host_id>.{crt,key}
                                ^
                                |
  argos-panel writes via the shared caddy_manual_certs volume
```

- The panel writes the uploaded cert + chain (concatenated, leaf
  first) to `<host_id>.crt` and the key to `<host_id>.key` on a
  named Docker volume (`caddy_manual_certs`). The volume is
  mounted read-write in argos-panel (`/data/manual-certs`) and
  read-only in argos-caddy (`/etc/caddy/manual-certs`).
- The key is **also** encrypted with AES-GCM (`crypto.Cipher`,
  same master key that encrypts OIDC client secrets) and persisted
  in `host_manual_certs.key_pem_encrypted`. That column is the one
  backups capture; the file on disk is a working copy Caddy reads.
- On the next reconcile, argos emits a
  `tls.certificates.load_files` entry pointing at those two paths.
  Caddy loads the pair at boot + on every config reload; SNI
  routing picks it when a browser asks for the host.
- No automation policy is emitted for the host, so Caddy NEVER
  tries to renew and NEVER contacts an ACME directory for it.

## Upload flow

1. **Open the host**. Hosts → pick the row → Edit.
2. **Flip TLS mode to `manual`**. The challenge radio disappears
   (manual certs are not issued by ACME) and a new **Manual
   certificate** section appears.
3. **Save the host first** if it is new. The upload form requires
   a host ID; the modal surfaces an amber note telling you so.
4. **Upload the files**. Three file pickers:
    - **Certificate** (`cert.pem`) — the leaf cert in PEM form.
    - **Private key** (`key.pem`) — the matching key in PEM form.
    - **Chain / intermediates** (optional) — any intermediate
      certs between your leaf and the root. Concatenated PEM.
5. **Click Upload & activate**. Argos validates:
    - PEM parses on both cert and key.
    - Key matches the cert (`crypto/tls.X509KeyPair`).
    - Cert is currently valid (`not_before` in the past,
      `not_after` at least 7 days in the future).
    - Cert's SAN list covers the host's domain
      (`x509.Certificate.VerifyHostname`, wildcards honoured per
      RFC 6125).
    - Chain (if provided) is a sequence of valid CERTIFICATE
      blocks (no key blocks mixed in).
6. **Warnings**. Non-fatal issues are echoed in the response:
    - "cert expires in Xd; consider renewing before upload" for
      anything under 30d.
    - "no intermediate chain provided; browsers may show
      'incomplete chain' warnings" for a non-self-signed cert
      with no chain.

On success the host flips to `tls_mode=manual`, the reconciler
pushes the new Caddy config within a second, and the cert is live.

## Files on disk

Inside the caddy_manual_certs volume:

```
<host_id>.crt   0644 nobody:nobody   leaf + chain concat
<host_id>.key   0644 nobody:nobody   private key, plaintext
```

Writing as `nobody` is the panel container's runtime user; caddy
reads as root (default for the upstream caddy image) so the 0644
permissions are adequate. Same threat model as Caddy's own
automated cert storage, which is also plaintext on disk.

## Renewal

There is none. You own it. Argos provides three signals:

- **Certificates → Imported tab** (`/certificates`) — status
  badge goes amber at 30 days, red at 7 days, dark red past
  expiry. Same thresholds as the Active tab.
- **Host edit modal → Manual certificate section** — the
  "Currently loaded" card shows `days_left` and the expiry
  relative time.
- **Notification event `manual_cert_expiring_soon`** — a daily
  cron fires this event at 30 / 14 / 7 / 1 days remaining. Wire
  a rule under **Notifications → Rules** pointing at whatever
  channel you use. Event payload includes the host domain,
  days remaining, the threshold crossed, and the cert
  fingerprint.

To renew: upload a fresh cert via the same form. The modal
surfaces a confirm dialog before replacing an existing cert so you
don't accidentally overwrite with the wrong file.

## Removing a manual cert

**Host edit → Manual certificate → Remove**, or **Certificates →
Imported → Remove** from the per-row action. Both:

1. Delete the cert + key files from the shared volume.
2. Delete the `host_manual_certs` row.
3. Flip the host back to `tls_mode=auto` (default) or `none`
   depending on the `revert` query param (defaults to `auto`).
4. Fire an audit row + reconcile Caddy.

If you go from manual → auto, the host will immediately try to
issue an ACME cert via its saved `tls_challenge`. Make sure that
challenge is still workable (DNS token still valid, port 80 still
open, etc.).

## Security considerations

- **Master key rotation** loses access to every encrypted key in
  the panel DB, including manual cert keys. If you need to rotate,
  re-upload every manual cert afterwards. Same constraint applies
  to OIDC client secrets.
- **Backups** capture `host_manual_certs.key_pem_encrypted` (AES-GCM
  encrypted) but NOT the plaintext `.key` file on the
  caddy_manual_certs volume (that volume is not in the backup
  scope). Restoring from backup restores the DB row; the panel
  re-writes the plaintext file to the volume on next startup
  reconcile if the volume is empty.
- **Plaintext on disk is inherent** to how Caddy's TLS module
  reads certs. Any shared-volume-based approach has this
  property; a compromise of the caddy container yields keys
  regardless of panel-side encryption.

## API

- `GET /api/manual-certs` — list every imported cert (metadata
  only, never the key).
- `GET /api/manual-certs/{host_id}` — one cert's metadata.
- `POST /api/manual-certs/{host_id}` — multipart upload
  (`cert_pem`, `key_pem`, optional `chain_pem`).
- `DELETE /api/manual-certs/{host_id}?revert=auto|none` — remove.
- `GET /api/manual-certs/{host_id}/download` — download
  cert + chain PEM (key is never served).

## Related

- [Import own cert workflow](../workflows/import-own-cert.md) — step-by-step.
- [Reverse proxy → TLS challenges](reverse-proxy.md#tls-challenges) — when
  an auto challenge is a better fit.
- [Cert troubleshooting](../operations/cert-troubleshooting.md) — diagnosing
  issuance failures vs using manual as a workaround.
- [Notifications](notifications.md) — wiring the
  `manual_cert_expiring_soon` event.
