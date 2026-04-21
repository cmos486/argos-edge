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
- You need **DNS-01 manual**: your DNS provider has no native
  integration in argos-edge, and ports 80 / 443 are not reachable.
  Issue the cert out-of-band with
  [acme.sh](../tls/manual-dns-workflow.md) or `certbot --manual`,
  then import via this feature. The
  [Manual DNS workflow](../tls/manual-dns-workflow.md) documents
  the supported path end-to-end, including renewal every ~60 days.

If you are uploading a Let's Encrypt cert obtained via `certbot`
just to avoid wiring CLOUDFLARE_API_TOKEN — don't. Use `tls_challenge=http`
instead (see [Reverse proxy → TLS challenges](reverse-proxy.md#tls-challenges));
that keeps auto-renewal working.

!!! tip "No DNS API? Use acme.sh + Import"
    For automated cert issuance without a DNS API (small providers,
    LAN-only setups, or any zone you do not want to put behind a
    panel-held API token), the
    [Manual DNS workflow](../tls/manual-dns-workflow.md) walks
    through using `acme.sh --dns` to get a Let's Encrypt cert via
    manual TXT records and importing it here.

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

Upload happens from **Certificates → Imported tab → Import
certificate**. A dedicated modal lets you pick the target host
from a dropdown (alongside its current `tls_mode` and a "has
manual cert" flag), upload the three files, and confirm.

> Note on page placement: before v1.1.1 the upload form sat
> inside the host edit modal. HTML nested `<form>` elements
> flatten in the browser, which caused the upload submit to fire
> the outer host form (running `updateHost`) and silently skip
> the actual upload. The modal split in v1.1.1 is the fix; the
> host edit modal now only shows read-only cert info plus a link
> to the Certificates page.

1. **Open Certificates → Imported → Import certificate**.
2. **Host** dropdown — pick the host. The row label shows the
   current `tls_mode` ("auto" / "none" / "manual") and flags a
   host that already has a manual cert ("has manual cert").
3. **Warning**: if the selected host is currently `tls_mode=auto`,
   an amber banner explains that import flips it to `manual` and
   disables auto-renewal.
4. **Upload the files**. Three file pickers:
    - **Certificate** (`cert.pem`) — the leaf cert in PEM form.
    - **Private key** (`key.pem`) — the matching key in PEM form.
    - **Chain / intermediates** (optional) — any intermediate
      certs between your leaf and the root. Concatenated PEM.
5. **Click Import & activate** (or **Replace & activate** for a
   host that already has a manual cert). Argos validates:
    - PEM parses on both cert and key.
    - Key matches the cert (`crypto/tls.X509KeyPair`).
    - Cert is currently valid (`not_before` in the past,
      `not_after` at least 7 days in the future).
    - Cert's SAN list covers the host's domain
      (`x509.Certificate.VerifyHostname`, wildcards per RFC 6125).
    - Chain (if provided) is a sequence of valid CERTIFICATE
      blocks (no key blocks mixed in).
6. **Atomic side-effects**. The DB row + the host's `tls_mode=manual`
   flip land in a single SQL transaction. PEM files are then
   written to the shared volume; a Caddy reconcile triggers.
7. **Warnings**. Non-fatal issues are echoed inline in the modal
   after a successful import:
    - "cert expires in Xd; consider renewing before upload" for
      anything under 30d.
    - "no intermediate chain provided; browsers may show
      'incomplete chain' warnings" for a non-self-signed cert
      with no chain.

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

To renew: open **Certificates → Imported → Import certificate**
and pick the same host. The modal surfaces a confirm dialog
before replacing an existing cert so you don't accidentally
overwrite with the wrong file.

## Removing a manual cert

**Certificates → Imported → Remove** on the row.

1. Delete the cert + key files from the shared volume.
2. Delete the `host_manual_certs` row.
3. Flip the host back to `tls_mode=auto` (default) or `none`
   depending on the `revert` query param (defaults to `auto`).
4. Fire an audit row + reconcile Caddy.

If you go from manual → auto, the host will immediately try to
issue an ACME cert via its saved `tls_challenge`. Make sure that
challenge is still workable (DNS token still valid, port 80 still
open, etc.).

## Disaster recovery

What happens when you restore onto fresh infrastructure where the
`caddy_manual_certs` volume is empty (bare-metal rebuild, DR to
new hardware, wiped volumes):

1. The tar.gz backup captured `argos.db` which includes the
   `host_manual_certs` row for every manual cert (`cert_pem`
   plaintext, `key_pem_encrypted` AES-GCM-encrypted with
   `ARGOS_MASTER_KEY`, plus the chain).
2. On panel startup, after migrations and before the first Caddy
   reconcile, the boot reconciler walks every `host_manual_certs`
   row and checks the expected `.crt` + `.key` paths on the
   `caddy_manual_certs` volume.
3. For each row whose files are missing, it decrypts the key with
   the configured cipher and writes the two files atomically
   (tmp file + rename) with the same permission policy the upload
   path uses.
4. Caddy's first `/load` then finds the `load_files` entries and
   serves the manual cert immediately — no operator intervention,
   no re-upload.

What this means for backup strategy: **`argos.db` + `.env` is
sufficient to fully recover manual certs on fresh infra.** The
`caddy_manual_certs` volume contents are NOT required to be
captured out of band; the encrypted keys in the DB are the source
of truth, and the reconciler rematerialises the on-disk copies on
next boot. This is what makes the argos backup tarball a
self-contained DR unit.

The two things you MUST keep safe out of band:

- **`argos.db`** itself (in `argos_data` volume OR inside a
  tar.gz backup replicated off-host).
- **`ARGOS_MASTER_KEY`** from `.env`. Without it the encrypted
  keys in `host_manual_certs.key_pem_encrypted` are
  unrecoverable — the boot reconciler will surface a per-row
  `decrypt key` error and skip those rows. The panel still boots;
  the manual certs just stay unavailable until the key is
  restored (or the operator re-uploads every manual cert).

Idempotency: the reconciler is a no-op for rows whose files
already exist. Safe to run on every boot; does not overwrite a
file the operator may have hot-edited for debugging.

## Security considerations

- **Master key rotation** loses access to every encrypted key in
  the panel DB, including manual cert keys. If you need to rotate
  `ARGOS_MASTER_KEY`, re-upload every manual cert after the
  rotation (the DR reconciler above cannot decrypt with the new
  key). Same constraint applies to OIDC client secrets.
- **Plaintext on disk is inherent** to how Caddy's TLS module
  reads certs. Any shared-volume-based approach has this
  property; a compromise of the caddy container yields keys
  regardless of panel-side encryption.
- **Backup tarballs carry encrypted keys** (inside `argos.db`),
  not plaintext. Off-host replication of backups does not leak
  cert keys as long as `ARGOS_MASTER_KEY` is stored separately.

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
