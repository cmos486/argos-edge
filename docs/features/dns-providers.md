# DNS providers

!!! warning "v1.3.0-alpha — backend only"
    This page documents the sub-phase A backend. **There is no Settings
    UI yet** — provider credentials are configured via the
    `/api/dns-providers` API directly (curl / any HTTP client). The UI
    ships in sub-phase B (v1.3.0-beta). Everything described here is
    stable enough to dogfood; the data model + endpoints will not
    change shape in the UI step.

Before v1.3 the panel shipped with exactly one DNS provider for ACME
DNS-01: **Cloudflare**, with the token passed as the
`CLOUDFLARE_API_TOKEN` environment variable on the caddy container.
v1.3.0-alpha generalises that to a catalogue of providers whose
credentials live encrypted in the panel DB and are streamed inline
into the Caddy `/load` JSON at every reconcile.

## What shipped in sub-phase A

- **Two providers compiled into the Caddy image**:
    - `cloudflare` (unchanged from v1.2).
    - `route53` (AWS Route 53; new in v1.3.0-alpha).
- **Per-provider credentials in the DB**, AES-GCM-encrypted under
  `ARGOS_MASTER_KEY` (same master key that already protects OIDC
  client secrets, SMTP passwords, manual-cert private keys, the
  VAPID key).
- **Option 2 credentials pipeline**: decrypted values are inlined
  into the Caddy `/load` JSON on every reconcile. The panel never
  writes a new env var, the caddy container never restarts on
  credential rotation.
- **Per-host `tls_dns_provider` column**. Hosts that use
  `tls_challenge='dns'` now carry a provider name (default
  `cloudflare` for existing rows). Migration 025 backfills.
- **Legacy env-var import on boot**. If `CLOUDFLARE_API_TOKEN` is
  set in the panel's environment AND the `dns_providers` table has
  no cloudflare credentials, the env value is encrypted and
  imported on boot. Idempotent; logs a one-time INFO advising the
  operator to remove the env value from `.env` at their
  convenience. The env var continues to work as a fallback for
  one release; it is scheduled for removal in v1.4.

## API surface

All three endpoints live under the existing session-authed group at
`/api/dns-providers`.

### `GET /api/dns-providers`

Returns the catalogue joined with DB state. Credentials are NEVER
included.

```bash
curl -b cookies.txt http://localhost:8080/api/dns-providers
```

```json
[
  {
    "name": "cloudflare",
    "display_name": "Cloudflare",
    "enabled": false,
    "configured": false,
    "fields": [
      {"key": "api_token", "label": "API Token", "required": true,
       "placeholder": "Zone:DNS:Edit scoped token", "secret": true}
    ],
    "caddy_module": "cloudflare",
    "docs_url": "https://dash.cloudflare.com/profile/api-tokens"
  },
  {
    "name": "route53",
    "display_name": "AWS Route 53",
    "enabled": false,
    "configured": false,
    "fields": [
      {"key": "access_key_id", "label": "AWS Access Key ID", "required": true,
       "placeholder": "AKIAIOSFODNN7EXAMPLE"},
      {"key": "secret_access_key", "label": "AWS Secret Access Key",
       "required": true, "secret": true},
      {"key": "region", "label": "AWS Region", "required": false,
       "placeholder": "us-east-1 (default)"}
    ],
    "caddy_module": "route53",
    "docs_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
  }
]
```

### `GET /api/dns-providers/{name}`

Same shape, one provider.

### `PUT /api/dns-providers/{name}`

Sets `enabled` and `credentials`. Required-field validation runs
against the catalogue; unknown fields are rejected.

**Set Cloudflare credentials and enable:**

```bash
curl -b cookies.txt -X PUT http://localhost:8080/api/dns-providers/cloudflare \
    -H "Content-Type: application/json" \
    -d '{
          "enabled": true,
          "credentials": {
            "api_token": "your-scoped-cf-token"
          }
        }'
```

**Set Route 53 credentials and enable:**

```bash
curl -b cookies.txt -X PUT http://localhost:8080/api/dns-providers/route53 \
    -H "Content-Type: application/json" \
    -d '{
          "enabled": true,
          "credentials": {
            "access_key_id": "AKIA...",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "eu-west-1"
          }
        }'
```

**Disable a provider (keep credentials for re-enable):**

```bash
curl -b cookies.txt -X PUT http://localhost:8080/api/dns-providers/route53 \
    -H "Content-Type: application/json" \
    -d '{"enabled": false}'
```

**Rotate one secret, keep the others:** send the `__UNCHANGED__`
sentinel in the fields you do NOT want to rotate.

```bash
curl -b cookies.txt -X PUT http://localhost:8080/api/dns-providers/route53 \
    -H "Content-Type: application/json" \
    -d '{
          "enabled": true,
          "credentials": {
            "access_key_id": "__UNCHANGED__",
            "secret_access_key": "new-rotated-secret",
            "region": "__UNCHANGED__"
          }
        }'
```

On success a reconcile runs automatically, so the new creds land
on Caddy's running config within the same request. No container
restart needed.

## Host-level selection

Hosts that set `tls_challenge='dns'` now also carry
`tls_dns_provider`. The Host API PUT/POST accepts the new field:

```bash
curl -b cookies.txt -X PUT http://localhost:8080/api/hosts/1 \
    -H "Content-Type: application/json" \
    -d '{
          "domain": "example.com",
          "target_group_id": 1,
          "tls_mode": "auto",
          "tls_email": "ops@example.com",
          "enabled": true,
          "tls_challenge": "dns",
          "tls_dns_provider": "route53"
        }'
```

The backend rejects `tls_dns_provider` values that are not in the
catalogue, or that point at a provider row that is disabled or
missing credentials. Legacy compat: if the target provider is
`cloudflare` AND the legacy env var `CLOUDFLARE_API_TOKEN` is set,
the save succeeds even without a DB row (reconciler then emits the
env placeholder).

## Migration from v1.2

Operators upgrading from v1.2 have two choices:

1. **Do nothing for now.** Keep `CLOUDFLARE_API_TOKEN` in `.env`.
   The boot-time import encrypts it into the DB the first time the
   panel sees it; the env var continues to work as fallback until
   the row is populated. Eventually remove the env var when
   comfortable.
2. **Actively configure via API.** `PUT /api/dns-providers/cloudflare`
   with the token, then drop the env var on the next restart. The
   boot-time import sees the populated DB row and skips.

## Trust boundary note (Option 2)

Credentials are decrypted in the panel process at every reconcile
and inlined into the JSON pushed to `http://caddy:2019/load`. A
subsequent `GET /config/...` from inside the Caddy container will
return the plaintext credentials. The admin API listens only inside
the `argos_net` Docker network and is never published on the host,
so the trust boundary is the same as it was pre-v1.3 for the
CrowdSec bouncer API key placeholder. Anyone who can shell into
the caddy container could already read
`env | grep CLOUDFLARE` in v1.2. Formalising the admin-API
boundary in `docs/operations/persistence.md` is still on the list
for v1.3.0 GA.

## What's NOT here

- **Settings UI**. Sub-phase B.
- **Host form dropdown to pick a provider**. Sub-phase B.
- **Test-connection button** that pings the provider's API. Defer
  to v1.3.x; first cert-issuance already produces a clear error
  via `caddy_error` logs.
- **Tier 2 providers** (gandi, desec, ovh, duckdns, porkbun,
  hetzner, digitalocean, acmedns). Sub-phase C per
  [`docs/internals/dns-providers-analysis.md`](https://github.com/cmos486/argos-edge/blob/main/docs/internals/dns-providers-analysis.md).

## Related

- [Reverse proxy → TLS challenges](reverse-proxy.md#tls-challenges)
  — the existing options. DNS-01 now grows a provider dropdown in
  sub-phase B.
- [Manual DNS workflow](../tls/manual-dns-workflow.md) — the
  acme.sh + Import fallback for providers not yet in the native
  catalogue.
- [Persistence](../operations/persistence.md) — what the
  encrypted-at-rest promise covers. DNS provider credentials live
  in `argos.db`, backed up by the standard backup path.
