# Request flow

Four walk-throughs of the common paths: attacker blocked at the
edge, legitimate user on a ForwardAuth-protected host, OIDC login,
and background cron work.

## Attacker hitting a WAF-protected host

A scanner probing `/wp-login.php` on a host argos fronts.

```mermaid
sequenceDiagram
    participant C as Client (attacker)
    participant Cad as Caddy
    participant Bouncer as CrowdSec bouncer<br/>(in Caddy)
    participant LAPI as CrowdSec LAPI
    participant AppSec as CrowdSec AppSec<br/>:7422 (block)
    participant U as Upstream

    C->>Cad: GET /wp-login.php
    Cad->>Bouncer: is this IP banned?
    Bouncer->>Bouncer: check cached decisions
    alt banned
        Bouncer-->>Cad: 403
        Cad-->>C: 403
    else not banned
        Cad->>AppSec: forward original request
        AppSec->>AppSec: evaluate CRS rules
        alt CRS match, anomaly >= threshold
            AppSec-->>Cad: 403 (with rule id)
            Cad-->>C: 403
            Cad->>LAPI: emit http-probing event
            LAPI->>LAPI: scenario fires -> create decision
        else clean
            Cad->>U: reverse_proxy
            U-->>Cad: 404 (path does not exist)
            Cad-->>C: 404
        end
    end
```

Key properties:

- **Bouncer check is cache-resident.** No LAPI round-trip on the
  happy path; decisions are refreshed on a 15 s poll.
- **WAF runs in-band.** Caddy waits for AppSec to return a verdict
  before continuing. Latency budget is single-digit ms on matched
  rules, sub-ms on unmatched.
- **CrowdSec scenarios aggregate.** A single 404 does not ban;
  N of them in a time window does.

## Legitimate user on a ForwardAuth-protected host

```mermaid
sequenceDiagram
    participant C as Browser
    participant Cad as Caddy
    participant Argos as argos /auth/forward
    participant DB as SQLite
    participant U as Upstream

    C->>Cad: GET https://myapp.example.com/dashboard<br/>(cookie: argos_session=...)
    Cad->>Argos: forward_auth sub-request<br/>(X-Forwarded-*, Cookie)
    alt cache hit (30s TTL)
        Argos->>Argos: lookup(token) -> rec
    else cache miss
        Argos->>DB: SELECT session JOIN user WHERE token=?
        DB-->>Argos: row
        Argos->>DB: UPDATE sessions SET last_seen_at=NOW<br/>(throttled; skip if <5 min old)
        Argos->>Argos: cache put(token, rec, exp=now+30s)
    end
    Argos-->>Cad: 200 OK<br/>X-Auth-User, X-Auth-Email, X-Auth-Name, X-Auth-Provider
    Cad->>U: GET /dashboard<br/>(X-Auth-* copied on upstream request)
    U-->>Cad: 200
    Cad-->>C: 200
```

On a cookie miss the handler reconstructs the original URL from
Caddy's `X-Forwarded-{Proto,Host,Uri}` headers and returns a 302
to `panel.example.com/login?rd=<escaped-url>`. The panel's OIDC
(or password) flow mints a session cookie with `Domain=example.com`
so the next request on `myapp.example.com` carries it.

## OIDC login

```mermaid
sequenceDiagram
    participant B as Browser
    participant A as argos panel
    participant IdP as OIDC provider
    participant PS as PendingStore<br/>(in-memory, 10min TTL)
    participant DB as SQLite

    B->>A: GET /api/auth/oidc/login?rd=<url>
    A->>A: randBytes(state), randBytes(nonce),<br/>randBytes(verifier)
    A->>A: code_challenge = base64url(sha256(verifier))
    A->>PS: store pending{state, nonce, verifier, returnTo}
    A-->>B: 302 IdP?client_id=&redirect_uri=&state=&code_challenge=&nonce=
    B->>IdP: authenticate (password, MFA, passkey)
    IdP-->>B: 302 /api/auth/oidc/callback?code=&state=
    B->>A: GET /api/auth/oidc/callback
    A->>PS: lookup(state) -> pending
    alt not found or expired
        A-->>B: 302 /login?oidc_error=state_not_found
    else found
        A->>IdP: POST /token (code, code_verifier)
        IdP-->>A: id_token + refresh_token
        A->>A: Verify(id_token) -- issuer, audience,<br/>signature, expiry, nonce
        A->>DB: UPSERT users WHERE external_id=sub
        DB-->>A: user row
        A->>A: CheckAllowlist(email) + RequireEmailVerified
        A->>DB: INSERT sessions (token, user_id, expires_at)
        A-->>B: 302 safeReturnTo(rd)<br/>Set-Cookie: argos_session=...
    end
```

Key integrity properties enforced in sequence:

1. `state` is single-use and expires in 10 min.
2. `code_verifier` is never transmitted on the initial redirect
   (only the challenge is), so a leaked auth URL cannot recover
   the token.
3. `nonce` is compared against the id_token's nonce claim after
   signature verification.
4. Email allowlist + `email_verified` gate fire AFTER the id_token
   is trusted.
5. `safeReturnTo` rejects backslash, control chars, and
   off-domain URLs before issuing the final redirect.

## Background cron work

Argos runs several time-driven goroutines against the main context.

```mermaid
flowchart LR
    subgraph hourly[Every 6 hours]
      ret[retention cron]
    end
    subgraph daily[Daily at backup.schedule]
      bak[backup scheduler]
    end
    subgraph monthly[Day 5 at 03:00 UTC]
      geo[geoip downloader]
    end
    subgraph continuous[Continuous]
      ingestor[log ingestor tail]
      sweeper1[OIDC pending sweeper]
      sweeper2[TOTP challenge sweeper]
      sweeper3[ForwardAuth cache sweeper]
    end

    ret -->|DELETE old rows| db[(SQLite)]
    bak -->|VACUUM INTO + tar.gz| data[/data/backups/]
    bak -->|delete > retention_days| data
    geo -->|download mmdb| geodir[/data/geoip/]
    ingestor -->|batch INSERT| db
    sweeper1 & sweeper2 & sweeper3 -->|evict expired| mem[in-memory maps]
```

What each does:

- **retention cron** — every 6 h and once at boot: drops
  `log_entries` older than `logs.retention_days` OR beyond
  `logs.max_entries` cap, drops `login_attempts` + `totp_attempts`
  older than 24 h. Also runs `maybeVacuum()` which VACUUMs once
  a month on day 1 at 04:00 UTC.
- **backup scheduler** — matches the `backup.schedule` cron (default
  `0 2 * * *` = 02:00 UTC daily). Runs `VACUUM INTO` snapshot,
  tars with metadata.json + caddy_data, SHA-256s, records a
  `backups` row, then applies `backup.retention_days`.
- **geoip downloader** — hardcoded `0 3 5 * *` (day 5, 03:00 UTC).
  Pulls `db-ip-city-lite.mmdb.gz` and `db-ip-asn-lite.mmdb.gz`
  from the DB-IP mirror, gunzips, atomic rename into place. Plus
  a non-blocking run at first boot if either file is missing.
- **log ingestor** — constantly tails Caddy's access + error +
  WAF audit files, parses the structured JSON, batches 100-row
  INSERTs into `log_entries`. Also picks up audit entries
  enqueued by `Recorder.Record`.
- **sweepers** — garbage-collect per-subsystem in-memory maps.
  Low-frequency ticks (TTL/2 each).

All cron work logs to structured slog with the `source=audit`
shape when it mutates state; you can trail them in the Logs tab
with `source = audit`.

## Related

- [Components](components.md) — the container map.
- [Storage](storage.md) — SQLite tuning, migration runner.
- [Threat model](threat-model.md) — what each handler is
  defending against.
