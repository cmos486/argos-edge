# Feature 1 — DNS-01 manual with lego library

Technical analysis, v1.2 scoping. No implementation.

Baseline: HEAD `cac9071` (tag `v1.1.1`). Feature 5 (manual cert import,
encrypted-at-rest, boot reconciler, `manual_cert_expiring_soon` event)
is now in production.

Original deferral rationale: `/tmp/acme-v1.1-analysis.md` section 4.
That doc recommended deferring Feature 1, shipping Feature 5 first, and
re-evaluating once operator feedback came in. We are now at that gate.

---

## 1. Lego library assessment

### Current dependency footprint

```
$ grep -c '^' backend/go.sum    # ~170 lines
```

No ACME client is currently vendored. Caddy container has its own ACME
stack (certmagic + acmez) but it runs out-of-process over the admin API.
The panel has never spoken ACME directly.

### Lego status

- **Latest stable**: v4.34.0, April 15 2026.
- **Release cadence**: every 4-6 weeks through 2025-2026.
- **Maintenance**: actively maintained (v4.31/4.32/4.33/4.34 all in
  last four months).
- **License**: MIT. Compatible with argos-edge.
- **Module path**: `github.com/go-acme/lego/v4`.
- **Scope**: one Go module, ~180 DNS providers as subpackages, a CLI,
  and a library API. Each provider is a separate import path so you
  only pull what you use.

Minimum import graph if we use only the manual provider:

```
go-acme/lego/v4              (core: Client, Certificate, Registration)
go-acme/lego/v4/challenge
go-acme/lego/v4/challenge/dns01
go-acme/lego/v4/providers/dns/manual   (we will NOT use this -- see below)
go-acme/lego/v4/registration
go-acme/lego/v4/certificate
miekg/dns                    (indirect, authoritative NS resolver)
cenkalti/backoff/v4          (indirect)
go-jose/go-jose/v4           (already in our go.sum via OIDC)
```

Estimated LOC pull: ~15-25k lines for the core if we tree-shake DNS
providers. Acceptable under CLAUDE.md's "no heavy deps" rule if we pin
it narrowly.

### Critical gotcha — lego `manual` provider reads `os.Stdin`

`challenge/dns01.DNSProviderManual.Present()` does:

```go
reader := bufio.NewReader(os.Stdin)
_, _ = reader.ReadBytes('\n')
```

It is a CLI-only solver. It prints TXT instructions to stdout and
blocks on stdin. In a daemon with no TTY, it would hang forever (or
EOF immediately if stdin is closed).

**We cannot reuse the stock manual provider.** We must write our own
`challenge.Provider` implementation that:

- Stores (domain, TXT name, TXT value) into `acme_orders`.
- Emits a notification.
- Blocks on a `chan struct{}` or a ctx-cancelled wait until the user
  hits Verify.
- On CleanUp, flips the order state (no actual DNS deletion since the
  user owns the record).

This is not a lot of code (~80 LOC), but it invalidates the "lego gives
it to us for free" framing from the v1.1 analysis.

### Second critical gotcha — lego orchestration is synchronous

`lego.Client.Certificate.Obtain()` runs the whole order in one call:
finalize account -> new order -> challenge -> Present() -> poll -> get
cert. Present() blocks inside that call. Our user wait can be hours to
days (they need to log into their DNS provider, add a TXT record, wait
for propagation).

Two strategies:

**A) Goroutine per order (lego-native):**
- One goroutine per in-flight order calls `Obtain()`.
- Present() blocks on a per-order `ready` channel.
- HTTP handler `POST /verify` closes the channel, Present() returns,
  lego polls CA, cert comes back on a result channel.
- State lives in memory.

Problems: panel restart (config reload, crash, container replace) kills
every in-flight goroutine. User's TXT record is still live but the
order context is gone. User has to re-trigger.

Bad UX for renewals where we notify the user and then they click Verify
3 days later — 3 days is long enough that any panel restart in between
loses their work.

**B) Persist the order state, drive it ourselves (low-level ACME):**
- We own the state machine in `acme_orders`.
- Each transition reads order URL + account key from DB, makes one
  ACME request, writes back.
- Panel restart resumes from the row.

This is the only viable design for renewal auto-scheduling.

**B implies we want a lower-level library than lego.** lego's ergonomic
win is `Obtain()`. If we bypass `Obtain()` and drive acme/v2 primitives
directly, lego's advantage over alternatives shrinks.

### Alternatives

**`github.com/mholt/acmez/v3`** (Apache-2.0, active, v3.1.6 Feb 2026)
- Split into `acme` (protocol plumbing) and `acmez` (porcelain).
- "Bring your own solver" — implements RFC 8555 without building in DNS
  providers. This is exactly what we need.
- Written by the Caddy author; same design vocabulary as the rest of our
  stack.
- Much smaller: ~88 total commits, zero DNS-provider baggage.
- `acmez.Solver` interface: `Present(ctx, chal)` + `CleanUp(ctx, chal)`
  + optional `Wait(ctx, chal)` hook that is explicitly built for "wait
  for DNS to propagate before telling the CA to validate". This matches
  our flow much better than lego's `Obtain()`.

**`golang.org/x/crypto/acme`** (BSD-3-Clause, already transitively used)
- ACME v2 protocol primitives only. No porcelain.
- `Client.DNS01ChallengeRecord(token) (string, error)` returns the TXT
  value; caller is fully responsible for everything else.
- Lowest dep cost (nothing new in go.sum).
- Highest code cost: ~300 LOC of glue to do what acmez gives in ~80.

### Recommendation on library

**Use acmez, not lego.** Rationale:

1. We do not need lego's DNS-provider catalogue — we provide our own
   solver.
2. We DO need a split plumbing/porcelain API where we can drive one
   step at a time, persist state between steps, and survive restarts.
   acmez is designed for that; lego is designed around a synchronous
   `Obtain()`.
3. Smaller dep, matches Caddy's design philosophy, Apache-2.0 is still
   compatible.
4. lego's `manual` provider buys us nothing because it is stdin-driven
   — we would rewrite it anyway.

If we are being strict about deps and willing to write 200 more LOC,
`x/crypto/acme` is also reasonable. Not recommended: the bespoke code
is where bugs live, and acmez has better docs + test coverage for the
weird cases (EAB, authz reuse, ARI/renewal info).

**The task asks about lego specifically.** The honest answer is: lego
is a fine library, but for our orchestration model acmez is a strictly
better fit. I recommend we change the library choice now rather than
discover this mid-implementation.

---

## 2. Lego manual provider API (for the record)

Even though we are not using it, here is what the original plan
assumed:

```go
// providers/dns/manual
type DNSProvider = dns01.DNSProviderManual
func NewDNSProvider() (*DNSProvider, error)

// Implements challenge.Provider:
//   Present(domain, token, keyAuth string) error   -- prints, reads stdin
//   CleanUp(domain, token, keyAuth string) error   -- prints, reads stdin
//   Timeout() (timeout, interval time.Duration)    -- 60m / 2s defaults
```

Signals: stdout prints instructions, stdin blocks. There is no
programmatic callback surface. There is no channel, no context,
nothing listenable.

If we did use lego, the integration pattern would be:

1. Write our own type implementing `challenge.Provider` (not use `manual`).
2. Override `Timeout()` to return something generous (24h+).
3. In `Present()`, persist the order row, emit notification, block on
   a per-order channel.
4. Register it via `client.Challenge.SetDNS01Provider(ourProvider)`.
5. Call `client.Certificate.Obtain(...)` in a goroutine bound to the
   order row.
6. HTTP `POST /verify` closes the channel.
7. `Obtain()` returns; we persist the cert.

This works but bakes in the "one goroutine per order, no restart
survival" limitation noted above. That limitation is the deal-breaker.

---

## 3. Proposed architecture

### a) DB schema changes

**Migration 024: extend `hosts.tls_challenge` CHECK**

Current (migration 022):
```sql
CHECK (tls_challenge IN ('dns', 'http', 'tls-alpn'))
```

New:
```sql
CHECK (tls_challenge IN ('dns', 'http', 'tls-alpn', 'dns-manual'))
```

Same `writable_schema` rewrite pattern as migration 023 used for the
`tls_mode` CHECK. Go-based migration, not plain SQL.

**Migration 025: new `acme_orders` table**

```sql
CREATE TABLE acme_orders (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id            INTEGER NOT NULL,
    state              TEXT NOT NULL DEFAULT 'pending'
                         CHECK (state IN (
                            'pending',
                            'awaiting_dns',
                            'validating',
                            'issued',
                            'failed',
                            'cancelled')),
    order_url          TEXT NOT NULL DEFAULT '',
    auth_url           TEXT NOT NULL DEFAULT '',
    challenge_url      TEXT NOT NULL DEFAULT '',
    txt_record_name    TEXT NOT NULL DEFAULT '',
    txt_record_value   TEXT NOT NULL DEFAULT '',
    cert_key_encrypted BLOB,
    cert_pem           TEXT NOT NULL DEFAULT '',
    chain_pem          TEXT NOT NULL DEFAULT '',
    error_message      TEXT NOT NULL DEFAULT '',
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_verified_at   DATETIME,
    completed_at       DATETIME,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);
CREATE INDEX idx_acme_orders_host_id ON acme_orders(host_id);
CREATE INDEX idx_acme_orders_state ON acme_orders(state)
    WHERE state IN ('awaiting_dns', 'validating');
```

**Migration 026: `acme_account` singleton table**

One shared ACME account for the panel, generated on first use. Rows
hold the encrypted account key + Let's Encrypt-registered URL.

```sql
CREATE TABLE acme_account (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    ca_directory_url    TEXT NOT NULL,
    email               TEXT NOT NULL,
    account_url         TEXT NOT NULL,
    private_key_encrypted BLOB NOT NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### b) Orchestration loop

**Package:** `backend/internal/acme/` (new)

Structure:
```
acme/
  client.go       -- wraps acmez.Client, loads/persists account
  orchestrator.go -- state-machine driver (run loop, resume after boot)
  solver.go       -- our acmez.Solver impl: writes to acme_orders
  orders.go       -- DB repo for acme_orders CRUD + state transitions
  renewal.go      -- cron that creates new orders ~60d before expiry
  errors.go       -- sentinel errors (ErrOrderExpired, ErrPropagation)
```

State machine:

```
            create order
   pending ------------> awaiting_dns
                              |
                      user clicks Verify
                              |
                              v
                         validating
                         /          \
                    ACME ok        ACME fail
                        |              |
                        v              v
                     issued          failed
                        |
                (reuse Feature 5 storage path)
```

Driver:

- **Create phase**: API endpoint `POST /api/hosts/:id/acme-orders`
  (or triggered by renewal cron). Calls `acmez.Client.NewOrder()`,
  derives the DNS-01 TXT value, stores everything in `acme_orders`
  row with state `awaiting_dns`. Emits `dns_manual_action_required`
  notification. Returns the TXT record to the UI.

- **Verify phase**: `POST /api/acme-orders/:id/verify`. Loads the row,
  runs authoritative-NS DNS check (see section 3c). On success:
  transitions to `validating`, calls `acmez.Client.InitiateChallenge()`
  to tell the CA to validate, polls authorization, on success calls
  `FinalizeOrder()`, downloads cert, persists to `host_manual_certs`
  (reusing Feature 5 schema), transitions to `issued`. On any failure:
  `failed` with `error_message`.

- **Resume phase**: on panel boot, scan `acme_orders WHERE state IN
  ('validating', 'awaiting_dns')`. For `validating` rows, poll CA to
  see if the authz completed while we were down. For `awaiting_dns`
  rows, do nothing — we are already durably waiting.

### c) DNS propagation check

We need to confirm the TXT record is live on authoritative NS before
telling Let's Encrypt to validate. Relying on the CA's self-check means
we waste our 5-validations-per-hour budget on "not yet" failures.

**Approach**: `miekg/dns` library (already transitively in go.sum via
lego if we go that route; a small new dep if we use acmez — ~4k LOC,
acceptable). Resolve the domain's NS records, then query each NS for
the TXT record directly (bypassing local recursive resolver cache).
Accept when at least one NS serves the correct value.

Retry: poll every 30s for up to 10 minutes from the `POST /verify`
click. If timeout, return a clear error to the UI ("record not found
on authoritative NS; check propagation and retry"). Do NOT silently
fail the order — leave it in `awaiting_dns`.

Alternative: trust acmez's built-in DNS-01 self-check
(`dns01.DefaultResolvers`). Simpler but uses local recursive resolvers
which can lie. Not worth the 5-failures/hour LE rate limit risk.

**Decision**: use miekg/dns directly. Small, well-known, correct.

### d) UI flow

**Host form:**

Add a fourth radio option to the existing tls_challenge group. Label:
"DNS-01 (manual TXT records)". Subtext warning: "Every cert renewal
(~60 days) will require you to add a new TXT record to your DNS. You
will be notified when action is needed."

Validation parallel to existing rules: `tls_challenge=dns-manual` is
only meaningful when `tls_mode=auto`; the check extends the existing
`api/hosts.go:417` block.

**Certificates page:**

Add an "ACME orders" sub-section. List orders grouped by host with
state badges. For `awaiting_dns` orders, highlight card with:

- Host domain
- TXT record name (`_acme-challenge.<domain>`)
- TXT record value (copy-to-clipboard)
- "Verify & continue" button
- "Cancel order" link (deletes the row, next cron creates a fresh
  one next tick if needed)

For `issued` orders, fold into the existing certs list.

For `failed` orders, show error + "Retry" button.

**Notifications:**

New notification event `dns_manual_action_required` in `notifications/
events.go`. Severity: Warning. Payload:

```json
{
    "domain": "example.com",
    "txt_name": "_acme-challenge.example.com",
    "txt_value": "abcd1234...",
    "order_id": 42,
    "panel_url": "https://panel.example.com/certificates#order-42"
}
```

Templates: email + slack + webhook copy that shows the TXT record AND
a deep-link into the panel.

### e) Renewal cron

Add to the existing `notifications/cron.go` `CertAndDetectCron.sweep()`
or a new `AcmeRenewalCron`. Cadence: hourly (acme_orders are rare
enough that 24h granularity on renewal is fine, but finer granularity
helps catch user-verify clicks that arrive between ticks).

Logic per tick:

1. Query hosts with `tls_mode='auto' AND tls_challenge='dns-manual'`.
2. For each, read current cert expiry from `host_manual_certs.not_after`
   (where the successful order wrote it).
3. If `days_until_expiry <= 60` AND no open `acme_orders` row exists
   for this host in state `awaiting_dns|validating|pending`: create
   one.
4. Emit `dns_manual_action_required`.

Rate-limiting: the `no open order` check prevents re-creating orders
for users who haven't acted yet. For the notification itself, rely on
the existing notification throttle (`notifications/throttle.go`).

---

## 4. Gotchas and risks

### a) Key-at-rest x2

Feature 5 already decided: encrypted key BLOB in DB + plaintext file
in `caddy_manual_certs` volume. Feature 1 inherits that. Consistent,
but it means:

- The issued key lands in the DB encrypted with the AES-GCM cipher
  (same `argos1:` prefix, same `ARGOS_MASTER_KEY`).
- It is also materialized plaintext on the volume so Caddy can serve
  it.
- Restore after volume wipe: boot reconciler (v1.1) re-materializes
  the plaintext. Same path, no new code.

Acceptable and consistent.

### b) Let's Encrypt rate limits

- 50 certs per registered domain per week (production).
- 300 new orders per account per 3 hours.
- **5 failed validations per account, per hostname, per hour.** This
  is the dangerous one.

Failure modes to avoid:

1. User adds wrong TXT value → propagation check catches it → we do
   NOT call CA validate → no rate-limit charge. Good.
2. User adds right TXT value, but TTL is still 24h and propagation
   incomplete → our pre-check fails → we do not call CA. Good.
3. We skip our pre-check and let CA validate → each failure burns the
   quota. Bad.

**Mitigation**: ALWAYS run the authoritative-NS pre-check before
InitiateChallenge. Document this in package comments.

Additional: exponential backoff on CA-side failures. After a
`validating -> failed` transition, require a 1-hour cool-down before
the user can re-trigger the same order. State this in the UI.

### c) Expiry strict mode

Question: cert expires and renewal was not completed — what does
Caddy serve?

Current Feature 5 behavior: Caddy serves whatever is in the
`caddy_manual_certs` volume. If the plaintext file is still the old
expired cert, browsers get an expired cert. If we remove the file,
Caddy's `load_files` fails and the host 404s.

**Proposed Feature 1 behavior**: identical. Nothing automatic. The
operator explicitly opted into "I am the renewal mechanism". Failing
loud (browser expired-cert warning) is better than silently falling
back to self-signed (which would break pinning + HSTS).

A future sub-feature could auto-transition `tls_mode` to `none` after
N days expired to let Caddy issue a temporary self-signed. Out of
scope for v1.2.

### d) ARGOS_MASTER_KEY dependency

Feature 5 already documented: lose the key, lose decryptability of
all encrypted BLOBs. Feature 1 adds:

- Account private key (in `acme_account.private_key_encrypted`).
- Order private keys (in `acme_orders.cert_key_encrypted` while
  in-flight).

Blast radius impact: same failure mode, more rows affected. The mit
remains the same — document it in `docs/operations/persistence.md`
and make sure the backup tar includes the key file (it already does
via `docker-compose.yml` env pass-through; check against v1.1
docs to confirm nothing changes).

### e) Order state machine + panel restart

acmez design makes this clean:

- We persist `order_url`, `auth_url`, `challenge_url` from the initial
  NewOrder response.
- On restart, any `validating`-state row calls `acmez.Client.GetOrder(
  order_url)` to re-fetch CA state.
- `awaiting_dns` state requires nothing from memory; user click drives
  it.

No in-memory `lego.Client` to lose.

Edge: if panel is down when LE sends the validation confirm, we miss
the transition window but can poll the order URL post-restart and
catch up. acmez's order URL is stable for ~7 days per LE.

### f) Account key scope

**Proposal: one global account key per ACME CA URL.**

Reasons:

- Multiple per host = N accounts = N rate-limit buckets, but also N
  more keys to manage.
- The `tls_email` on each host stays the human "who to notify" label;
  the ACME account's email is the panel's admin email (new setting).
- If the user wants to switch CAs (LE prod -> staging -> Buypass), we
  create a new account row per CA URL. `acme_account.id` stops being
  a singleton — change to `(ca_directory_url UNIQUE)`.

Storage: one row per CA, account private key encrypted with the
master key.

First-use flow: first time anyone selects `tls_challenge=dns-manual`,
the orchestrator sees no `acme_account` row, generates an ECDSA P-256
key, registers with LE, persists. No UI required — admin email reuses
the panel admin address (new setting `acme_contact_email`).

---

## 5. Complexity estimate

| Component | Effort | Notes |
|-----------|--------|-------|
| DB migrations (024, 025, 026) | S | Enum extension + 2 new tables. Existing patterns in place. |
| acme package + acmez wrapper  | L | Account mgmt, order create, solver, resume-on-boot. New package, new library. |
| acme solver + DNS propagation | M | miekg/dns queries, retry loop, error classification. |
| Orchestrator state machine    | L | 6 states, boot-resume, idempotency, transactional transitions. Unit-heavy. |
| HTTP API (create/verify/list) | M | 4-5 endpoints, permission gating, response shapes. |
| UI: host form option          | XS | One radio, one warning block. |
| UI: orders page/section       | M | New component, polling, state badges, verify flow. |
| Renewal cron                  | S | Extends existing cron pattern. |
| Notifications (new event)     | S | Events catalog entry + 3 templates. |
| Tests (integration + unit)    | L | Pebble harness + miekg/dns fakes + state transitions. |
| Docs                          | M | New workflow page, DR section update, screenshots. |

Total: **HIGH**. 3-5 focused weeks, closer to 5 if we want the test
harness right.

---

## 6. Proposed sub-phasing

The feature is big enough that splitting is healthy.

**Sub-phase A — ACME core (backend-only, no UI):**
- Migrations 024/025/026.
- `acme` package: client, solver, orchestrator, orders repo.
- Authoritative-NS propagation check.
- API endpoints for create/verify/list orders (JSON, no UI).
- Pebble-backed integration tests.
- Internal-only; users can trigger via curl.

Ships as `v1.2.0-alpha`. Merges in a single branch, can sit for a
release cycle while we dogfood it on the homelab.

**Sub-phase B — UI flow:**
- Host form radio option.
- Orders page / section.
- Verify button.
- Copy-to-clipboard affordance.

Ships as `v1.2.0-beta`.

**Sub-phase C — Automation + notifications:**
- Renewal cron.
- `dns_manual_action_required` event + templates.
- End-to-end renewal test.

Ships as `v1.2.0` GA.

This ordering matches the Feature 5 phasing (core -> UI -> notifications)
and lets us stabilize each layer.

---

## 7. Testing infrastructure

### Unit

- Solver with fake channel signals (Present/Wait/CleanUp ordering).
- Orchestrator state machine, table-driven transitions, error injection
  per step.
- Authoritative-NS resolver with miekg/dns test server.
- Migrations: up/down/up cycle with writable_schema.

### Integration

- **Pebble** (letsencrypt/pebble): official ACME test CA, Go-written,
  Docker image available. Runs locally, accepts any domain, returns
  short-lived certs. Our test suite spins up pebble in a sidecar
  container, points `acme_account.ca_directory_url` at it, drives a
  full order lifecycle against a fake DNS server we control.
- **Fake DNS server**: miekg/dns can run a test authoritative server
  on 127.0.0.1:5353. Tests write TXT records to this server before
  clicking Verify.
- End-to-end: create order -> poll TXT in solver -> verify -> validate
  -> finalize -> cert in DB -> cert file on disk. 30-45 seconds per run
  with pebble.

### Manual staging

- One-time dogfood against LE staging
  (`https://acme-staging-v02.api.letsencrypt.org/directory`) with a
  real domain we control. Not in CI.

### Effort

- Pebble harness + fake DNS: 2-3 days.
- Unit coverage: 2 days.
- Can be done in parallel with implementation.

---

## 8. Do we still need this? (The real question)

Feature 5 ships. Our alternative story now is:

> "Run `acme.sh --dns manual --issue -d example.com` on any shell,
> follow the TXT prompts, then use the argos-edge Certificates page
> Import button to upload the resulting cert + key."

That is 5 commands and one upload. Renewal is the same dance every
~60 days.

### Pros of argos-edge-native DNS-01 manual (Feature 1)

- One tool, one UI. No `acme.sh` install, no shell, no context switch.
- Notifications for renewal already come from the panel.
- Automatic renewal orchestration (user only clicks Verify when
  prompted — no calendar reminder, no manual `acme.sh --renew`).
- Integrated audit log.

### Cons

- 3-5 weeks of work.
- New critical path: any bug in the state machine breaks cert issuance.
- Larger blast radius for `ARGOS_MASTER_KEY` loss.
- One more ACME client in the stack (Caddy has its own for `dns` mode;
  now the panel has a second one for `dns-manual` mode).

### What we know about actual demand

`/tmp/acme-v1.1-analysis.md` explicitly gated this decision on "user
feedback demand after Feature 5 ships". As of HEAD v1.1.1:

- Feature 5 shipped 2 days ago.
- No user feedback yet (the homelab user is you; this is a
  single-operator project).
- No issues filed asking for DNS-01 manual.
- No repeat friction from the `acme.sh + Import` workflow documented.

### Recommendation

**Defer Feature 1 to v1.3 or later. Do not start implementation now.**

Specifically:

1. Document the `acme.sh --dns manual` workflow as the supported path
   for operators whose DNS provider has no API. One new markdown page
   under `docs/tls/manual-dns-workflow.md`.
2. Add a short hint in the host form when `tls_challenge=dns` is
   selected without a configured `CLOUDFLARE_API_TOKEN`:
   "Your DNS provider is not supported natively. See [manual DNS-01
   workflow]." Keep the user in the product without having to build
   the whole feature.
3. Re-evaluate after 90 days of Feature 5 being in use. The trigger
   for green-lighting Feature 1 is concrete friction: the operator
   explicitly says "I am sick of `acme.sh` dancing every 60 days,"
   or we add a second user whose workflow is blocked.
4. If we do revisit, use acmez not lego. Update the original v1.1
   analysis to reflect this finding.

The honest reading of the evidence: Feature 5 may have subsumed 90%
of the user need. Building Feature 1 now is speculative scope for a
one-user homelab project. The v1.1 analysis guessed right — ship the
simpler thing first, see if the gap hurts, build the complex thing
only if it does.

**Action for the user**: read this doc; decide between (a) defer per
this recommendation, or (b) green-light sub-phase A anyway because
you know you will want it. If (b), the estimate is 1-2 weeks for
sub-phase A alone, and the blast-radius warning stands.

---

## Appendix — deltas vs. the original v1.1 analysis

1. Original assumed lego was the library. This analysis finds acmez
   is the better fit because (a) lego's manual provider is stdin-only,
   (b) lego's synchronous `Obtain()` does not match our durable-order
   requirement. Switching libraries invalidates part of the original
   "Option 2" design in sections 4 and 5 of `acme-v1.1-analysis.md`.
2. Original did not call out the LE 5-failures/hour rate-limit risk
   with enough force. Any implementation MUST have authoritative-NS
   pre-check before CA validation.
3. Original proposed one-account-per-host. This analysis argues for
   one-account-per-CA-URL (one global by default) for operational
   simplicity.
4. Original did not discuss panel-restart survival. This is the single
   biggest design constraint and the reason for picking acmez over
   lego.
