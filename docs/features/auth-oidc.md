# OIDC SSO

Argos speaks OIDC Authorization Code + PKCE. Any compliant provider
works. This page covers the generic setup, then vendor-specific
steps for the five providers most homelab operators run.

## What argos needs from the provider

Every provider setup ends with the same three values pasted into
**System → Single sign-on**:

- **Issuer URL** — the OIDC discovery root. Argos fetches
  `<issuer>/.well-known/openid-configuration` and pins the JWKS
  URL from there.
- **Client ID** — the OAuth client identifier you created at the
  provider.
- **Client secret** — the matching secret. Encrypted at rest with
  `ARGOS_MASTER_KEY` (AES-GCM, fresh nonce per save).

Plus one redirect URI to register at the provider:

```
<panel_scheme>://<panel_domain>/api/auth/oidc/callback
```

Visible in the panel's **System → Single sign-on → Redirect URI**
box, with a copy button. The exact string the provider must have
on its allow-list.

## Flow

1. User hits `/login` and clicks **Sign in with SSO**.
2. Panel calls `/api/auth/oidc/login` which creates a server-side
   `state` + `nonce` + PKCE `code_verifier`, stores them in an
   in-memory pending store (10-min TTL, single-use), then 302s the
   browser to the provider with `code_challenge=S256(verifier)`.
3. Provider authenticates the user (password, MFA, passkey, etc.),
   redirects back to `/api/auth/oidc/callback?code=...&state=...`.
4. Argos validates the state (single-use, not expired), exchanges
   the code for tokens using the stored `code_verifier`, validates
   the id_token (signature, issuer, audience, expiry, nonce), and
   extracts claims (`sub`, `email`, `email_verified`, `name`,
   `preferred_username`).
5. Argos upserts the user keyed by `(external_provider='oidc',
   external_id=sub)`, applies the allowlist, optionally enforces
   `email_verified`, mints a session cookie, 302s back to the
   original destination.

The state cookie is single-use and consumed on the first
successful callback. A replay with the same state fails.

## Configuration surface (panel side)

**System → Single sign-on**:

| Field | Notes |
|---|---|
| Enable single sign-on | Master toggle. Off = /api/auth/oidc/* returns 404. |
| Issuer URL | Discovery root. |
| Client ID | OAuth client id. |
| Client secret | Keep blank on re-save to keep the stored value. |
| Scopes | Space-separated. `openid` is required and auto-added. Defaults to `openid email profile`. |
| Cookie parent domain | For ForwardAuth across subdomains. See [ForwardAuth](forward-auth.md). |
| Auto-provision | On: first-time users are created; off: first-time users are rejected. |
| Require verified email | On: reject when id_token has `email_verified=false` or missing. Default off for backcompat. |
| Allowed emails | Exact lowercase match. Empty = allow any authenticated user. |
| Allowed domains | Domain part of email, exact match. `example.com` matches `a@example.com` NOT `a@sub.example.com`. |

Save runs a discovery probe against the issuer before persisting,
so invalid URLs fail fast.

## Provider walkthroughs

Five providers below. Each ends with the three values to paste
into the panel.

### Google Workspace / Google Cloud

1. Go to <https://console.cloud.google.com/>, pick or create a
   project.
2. **APIs & Services → OAuth consent screen**. User type
   *Internal* for Workspace domains, *External* for personal
   projects. Fill app name + support email.
3. **APIs & Services → Credentials → Create Credentials → OAuth
   client ID**.
    - Application type: **Web application**.
    - Authorized redirect URIs: paste the value from argos'
      **Redirect URI** box.
4. Save. Copy the **Client ID** + **Client secret** shown.
5. On argos:
    - Issuer URL: `https://accounts.google.com`
    - Scopes: `openid email profile`
    - Allowed domains: your Workspace domain
    - Require verified email: **on**

Notes:

- Google signs with rotating keys; the discovery URL + JWKS handle
  rotation transparently.
- Internal-user mode means only accounts in your Workspace org can
  sign in, in addition to argos' allowlist.

### Microsoft 365 / Azure AD

1. <https://portal.azure.com> → **Microsoft Entra ID** (formerly
   Azure AD) → **App registrations → New registration**.
2. Name: `argos-edge`. Account type: whichever matches your
   tenancy (single-tenant is simplest).
3. Redirect URI: **Web**, paste the value from argos.
4. After creation:
    - **Certificates & secrets → New client secret**. Copy the
      *Value* (not the secret id).
    - **API permissions → Add → Microsoft Graph → Delegated**: at
      minimum `openid`, `email`, `profile`. `User.Read` is added
      by default; keep it.
5. Application (client) ID + Directory (tenant) ID are visible on
   the app's Overview page.
6. On argos:
    - Issuer URL:
      `https://login.microsoftonline.com/<tenant-id>/v2.0`
    - Scopes: `openid email profile`
    - Allowed domains: your tenant's verified domains

Notes:

- The v2.0 issuer URL is important. v1.0 returns tokens with
  different claim names that argos' parser does not expect.
- The `email` claim may come from the `upn` attribute depending on
  tenant config; Microsoft sometimes maps these interchangeably.

### Authentik (self-hosted)

1. Authentik UI → **Applications → Providers → Create**.
    - Type: **OAuth2/OpenID Provider**.
    - Name: `argos-edge`.
    - Authorization flow: `default-provider-authorization-implicit-consent`
      (or explicit, whichever your org policy wants).
    - Signing key: any with RS256 support (Authentik ships with
      defaults).
    - Redirect URI: paste argos' value. **Strict** mode is fine.
2. After save, copy **Client ID** and **Client Secret** from the
   provider detail.
3. **Applications → Applications → Create**. Attach the provider.
   Slug can be `argos`.
4. On argos:
    - Issuer URL:
      `https://<your-authentik-host>/application/o/argos/`
      (trailing slash matters).
    - Scopes: `openid email profile`
    - Cookie parent domain: set to the parent shared by panel +
      target hosts.

Notes:

- Authentik's discovery root is the application-slug-scoped URL.
  The top-level `/application/o/` without a slug does not work.
- Enforce MFA in Authentik's own flow; argos' local TOTP is NOT
  applied to OIDC users.

### Authelia

1. Edit Authelia's `configuration.yml`:

```yaml
identity_providers:
  oidc:
    hmac_secret: <32+ random chars>
    jwks:
      - key_id: main
        algorithm: RS256
        key: |
          -----BEGIN RSA PRIVATE KEY-----
          ...
          -----END RSA PRIVATE KEY-----
    clients:
      - client_id: argos-edge
        client_name: "Argos Edge"
        client_secret: <keep this matching what you paste in argos>
        public: false
        authorization_policy: two_factor
        redirect_uris:
          - https://panel.example.com/api/auth/oidc/callback
        scopes:
          - openid
          - email
          - profile
        token_endpoint_auth_method: client_secret_post
```

2. Restart Authelia.
3. On argos:
    - Issuer URL: `https://<authelia-host>`
    - Client ID: `argos-edge`
    - Client secret: the value from config
    - Scopes: `openid email profile`

Notes:

- Authelia's `authorization_policy` controls whether MFA is
  required during the OIDC handshake. `two_factor` forces it for
  this client.
- `token_endpoint_auth_method: client_secret_post` matches what
  argos sends; `client_secret_basic` also works.

### Keycloak

1. Keycloak admin UI → **Clients → Create client**.
    - Client type: OpenID Connect.
    - Client ID: `argos-edge`.
2. Capability config: enable **Client authentication** (so a
   secret is generated). Standard flow on, Implicit + Direct
   access + Service accounts off.
3. **Login settings** → Valid redirect URIs: paste argos' value.
4. After creation: **Credentials** tab → copy **Client secret**.
5. On argos:
    - Issuer URL:
      `https://<keycloak-host>/realms/<realm-name>`
    - Client ID: `argos-edge`
    - Client secret: from the Credentials tab
    - Scopes: `openid email profile`

Notes:

- Keycloak's issuer is realm-scoped. Master realm is for admin
  only; create a purpose-specific realm for argos users.
- `email_verified` claim is populated from the user's "Email
  verified" profile flag. Turn **Require verified email** on in
  argos.

## Testing the connection

**System → Single sign-on → Test connection**. Argos runs a
discovery fetch against the issuer and surfaces what the provider
advertised:

- Issuer the provider reports (sanity-check this matches the URL
  you typed).
- Authorization endpoint.
- Token endpoint.
- Userinfo + JWKS URLs if advertised.
- Signing algorithms supported.

Discovery failures show as red in the UI. Most common: the issuer
URL has a typo, is behind authentication that blocks unauthed
fetches, or the cert chain is not trusted by the Go default pool.

## Allowlisting

The two fields work together:

- An identity is **accepted** if its email is on `allowed_emails`
  OR its email domain is on `allowed_domains`.
- Both empty: every authenticated identity the IdP sends is
  accepted (permissive-trust mode; safe only when the IdP is
  itself tightly controlled, like an Authentik with a pre-approved
  user list).
- The email_verified gate (when enabled) runs BEFORE the allowlist
  check, so an attacker cannot probe the allowlist by sending
  unverified emails at known domains.

## Gotchas

- **Panel cookie parent domain must cover every protected host.**
  Set it BEFORE adding hosts under ForwardAuth; switching it
  invalidates every existing session.
- **OIDC users bypass argos TOTP.** The IdP is authoritative for
  MFA. If the IdP has no MFA, the argos account has no MFA.
- **Break-glass** — the bootstrap local admin is NOT OIDC. Keep
  their password + TOTP recovery codes. An IdP outage that breaks
  SSO does not lock you out of the panel.
- **`auto_provision=off` is restrictive.** With it off, there is no
  UI path to pre-create OIDC user rows; the only way is direct SQL.
  Leave on unless you are deliberately operating a closed set.
- **Changing client_secret rotates correctly.** Save with the new
  value in the Client Secret field; the previous ciphertext is
  overwritten with a fresh AES-GCM nonce.

## Related

- [ForwardAuth](forward-auth.md) — put backends behind the same
  session cookie.
- [Publish with SSO](../workflows/publish-with-sso.md) —
  operational walkthrough.
- [Onboard an admin](../workflows/onboard-admin.md) — allowlist +
  auto-provision.
