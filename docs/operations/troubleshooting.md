# Troubleshooting

Problems grouped by what the operator would search for.

## Panel unreachable

### Browser cannot reach `http://<lan-ip>:8080`

Check in order:

1. `docker compose ps` — is `argos` up and `healthy`?
2. `docker compose logs argos --tail=50` — any fatal error at
   boot (missing env var, DB lock, etc.)?
3. `docker compose exec argos wget -qO- http://localhost:8080/healthz`
   — does the container answer its own port? If yes, the problem
   is the host firewall or the port publication.
4. `netstat -tlnp | grep 8080` on the host — is the port actually
   bound?

### `ARGOS_MASTER_KEY is required`

The binary refuses to boot without a 32-byte master key. Generate
and set:

```bash
echo "ARGOS_MASTER_KEY=$(openssl rand -hex 32)" >> .env
docker compose up -d
```

### `ARGOS_SESSION_SECRET is required`

Same story, separate key (can be any length, 32 bytes recommended).

## Login issues

### "Incorrect password" despite the right password

- Bootstrap runs once. If you changed `ARGOS_INITIAL_ADMIN_PASSWORD`
  after first boot, it did NOT update the existing row. Either
  log in with the original password, or break-glass via SQL:

```bash
docker compose exec argos sh -c '
  HASH=$(htpasswd -bnBC 12 "" "new-password" | sed -e s/^://)
  sqlite3 /data/argos.db "UPDATE users SET password_hash=\"$HASH\" WHERE username=\"admin\""
'
```

- Rate-limited? `login_attempts` has 5+ fails in 5 min for your
  IP → wait 30 min or:

```bash
docker compose exec argos sqlite3 /data/argos.db \
  "DELETE FROM login_attempts WHERE remote_ip='<your-ip>'"
```

### Lost TOTP authenticator + lost recovery codes

CLI break-glass:

```bash
docker compose exec argos argos disable-2fa --user admin --yes
```

Password alone logs you in after. Re-enroll TOTP once you are in.

### OIDC login loops

`/login` redirects to the IdP, IdP redirects back, argos 302s
back to `/login?oidc_error=...`. Read the query string; common
codes:

- `state_not_found` — the pending store does not have the state
  (expired 10-min TTL, or the callback arrived on a different
  argos instance). Re-click **Sign in with SSO**.
- `not_allowed` — the email is not on the allowlist. Check
  **System → SSO → Allowed emails / domains**.
- `no_auto_provision` — first-time user but `auto_provision` is
  off. Toggle it on or pre-create the row via SQL.
- `email_unverified` — `require_email_verified=true` AND the
  id_token's `email_verified` claim is false or missing. Fix in
  the IdP's user profile, or disable the flag if your IdP does
  not emit the claim.

## TLS / certs

### "Let's Encrypt: request failed"

- DNS not resolving: `dig +short myapp.example.com @1.1.1.1`
  should return your host's public IP.
- Port 80 blocked: Let's Encrypt HTTP-01 challenge requires :80
  open to your host. Test with an external HTTP check.
- Rate limit at Let's Encrypt: 5 cert failures per hostname per
  week. Check `docker compose logs caddy | grep -i 'rateLimited'`.

### Cert expiring / Caddy not renewing

- Check `docker compose logs caddy | grep renew` for the last
  renewal attempt error.
- **Certs tab** shows `last_checked_at`; if stale, Caddy has not
  attempted a renewal recently, which is a bug — restart caddy.

## Hosts / reverse proxy

### 502 Bad Gateway from argos-fronted host

The upstream is unreachable or refused the connection.

- `docker compose exec argos wget -qO- http://<upstream-ip>:<port>/`
  — can argos reach it?
- Upstream in a different docker network / on a different host?
  Argos needs to be on the same bridge or have a route to it.
- Upstream on an `https` URL with a self-signed cert and
  `verify_tls=true`? Either install a trusted cert on the
  upstream or toggle off verify_tls for that target group.

### 404 from caddy on a host that should exist

- **Hosts** tab: row enabled?
- **Logs** filter `source = caddy_error` for any reconcile error.
- `docker compose logs argos | grep reconcile` for push errors.
- As a last check, `curl http://localhost:2019/config/` (from
  inside argos) surfaces the currently-loaded Caddy config; grep
  for the host.

### New host does not get a cert

See [TLS / certs](#tls-certs) above. One extra check specific
to a newly-added host: `Caddy` tries the challenge on the first
request, not on config load. Hit the host once with `curl` and
the cert provisions.

## WAF

### Every request 403s after enabling block mode

- **AppSec tab**: the rule that is firing will be at the top.
- Likely a false positive on your own legitimate traffic. Add a
  narrow exclusion (path + rule id) and re-test.
- As a quick recover: flip the host's WAF mode back to `detect`
  while you tune.

### WAF audit logs empty

- Is the host's `waf_enabled` on?
- Is `appsec.mode` not `disabled`?
- `docker compose logs caddy | grep appsec` — the bouncer
  connecting to AppSec?
- `docker compose logs crowdsec | grep -i appsec` — the AppSec
  listener up?

### Every request to every host returns 500 with `dial tcp ... :7423: connect: connection refused`

Symptom, verbatim from `caddy_error.log`:

```
"logger":"crowdsec.appsec", "msg":"appsec component unavailable",
"error":"Get \"http://crowdsec:7423\": dial tcp ...: connect:
connection refused"
```

Cause: AppSec is configured on the panel (`appsec.mode != disabled`)
but the CrowdSec container has zero AppSec collections installed,
so nothing listens on :7422/:7423. **Only affects pre-v1.3.2**: the
bouncer plugin's historical default was fail-closed, so a dead
AppSec sidecar 500'd every request on every host.

**Fix: upgrade the panel to v1.3.2+.** The panel now defaults the
plugin's `appsec_fail_open` flag to `true`; a dead sidecar no
longer cascades into an outage. No other action required — the
500s stop on the next reconcile after upgrade.

After upgrade, pick one of three operating modes on the
[AppSec feature page](../features/appsec.md):

- **Scenario A** — accept AppSec-off as your steady state (no WAF
  inline, LAPI bouncer still blocks banned IPs, `appsec_unavailable`
  notification can be silenced by switching to Scenario C).
- **Scenario B** — install AppSec collections and use WAF inline
  (run `/setup-appsec.sh` inside CrowdSec, then
  `docker compose restart crowdsec caddy`; verify with
  `wget -qSO- -O /dev/null http://crowdsec:7423/` from the caddy
  container, expecting 403 or 200 — never connection refused).
- **Scenario C** — disable AppSec entirely on the panel (**AppSec
  → Change mode → Disabled**). Caddy stops emitting `appsec_url`,
  no round-trip, no notification. LAPI bouncer stays active.

Full walkthrough of each: [AppSec → The three scenarios](../features/appsec.md#the-three-scenarios).

### `appsec_unavailable` notification firing repeatedly

Expected behaviour: the notification fires ONCE per reachable →
unreachable transition, then goes quiet (consecutive failures are
suppressed; a successful probe resets the edge). If you see the
event re-firing every 5 minutes:

- Confirm the setup-appsec.sh run actually succeeded. The
  healthcheck counts HTTP 404 from the sidecar as unhealthy (the
  sidecar is up but has no collections to match) and will trigger
  the edge detector on every probe.
- `docker exec <crowdsec-container> cscli appsec-configs list`
  should show at least one row. Empty = setup did not persist.

If you actively do not want AppSec (Scenario C above), flip the
panel's **AppSec mode** to `disabled`. The healthcheck stops
probing when `appsec_url` is not emitted, and the notification
goes permanently quiet.

### CrowdSec logs: `missing API key` from the panel's IP every 5 minutes

Symptom — CrowdSec container log shows:

```
level=error msg="Unauthorized request from '172.20.0.4:...' (real IP = ):
              missing API key" module=acquisition.appsec
```

…repeating on a ~5 min cadence, always from the panel container's
IP (not the caddy container's IP).

Cause: pre-v1.3.4 the panel's AppSec health probe hit `:7423`
without sending the bouncer API key. The probe fired every 5
minutes and every probe produced one `missing API key` error line
on CrowdSec. Harmless (Caddy's request-time AppSec auth is
independent and was correctly sending the key), but alarming in
the log.

Fix: upgrade the panel to v1.3.4+. The health probe now sends
`X-Crowdsec-Appsec-Api-Key: <bouncer key>` on every request and
CrowdSec authenticates the probe cleanly. The log spam stops
immediately after restart.

If you still see it post-v1.3.4: the env var
`CROWDSEC_BOUNCER_API_KEY` differs between the panel and caddy
containers. Re-sync the key in `.env`, `docker compose up -d`.

### AppSec page shows "metrics unavailable: machine credentials missing"

Should be rare after v1.3.5. Machine credentials are bootstrapped
automatically by the `crowdsec-init` sidecar on first `docker
compose up` (see
[AppSec → Automatic bootstrap](../features/appsec.md#automatic-bootstrap-v135)).
If the banner shows up anyway:

- `docker compose ps` — is `argos-crowdsec-init` in state `exited
  (0)`? If not, check `docker logs argos-crowdsec-init` for why.
- `docker exec argos-crowdsec cscli machines list` — do you see an
  `argos-panel` row with `Auth Type: password`? Absent = init
  didn't run yet.
- In the panel: `GET /api/settings?prefix=crowdsec.machine` (via
  your session cookie). Both `crowdsec.machine_user` and
  `crowdsec.machine_password_encrypted` should be non-empty.
- If settings are populated but metrics still fail, the password
  may have been rotated out-of-band on the CrowdSec side. Force
  regeneration per the feature page's runbook.

Pre-v1.3.4 the same missing-credentials condition rendered as a
top-level red error: *"Could not load AppSec state: metrics from
lapi: crowdsec not configured"*. v1.3.4 scoped it to the metrics
area. v1.3.5 removes the condition entirely for fresh installs by
bootstrapping credentials automatically.

## CrowdSec

### Threats tab: "not configured"

- The machine credentials are empty. Run
  `cscli machines add argos-panel --password` inside the crowdsec
  container and paste the values.

### No bans happen despite obvious attacks

- `docker compose logs caddy | grep bouncer` — bouncer
  initialized? If it says `not configured`, `CROWDSEC_BOUNCER_API_KEY`
  in `.env` is missing or wrong.
- `cscli bouncers list` — is the bouncer row present?
- Scenario maturation: CrowdSec does not ban on a single
  suspicious request. It aggregates over a window — give it a
  few minutes of sustained attack traffic.

## Backup / restore

### Backup fails: "disk full"

- `df /var/lib/docker/volumes/argos-edge_argos_data/_data/backups`
  — how much free?
- Lower `backup.retention_days` to drop older archives, or add
  storage.

### Restore leaves the panel in a boot loop

Container sees `/data/.restore_pending`, tries to extract, fails.
Clear the marker:

```bash
docker compose exec argos rm -f /data/.restore_pending
docker compose restart argos
```

Panel boots on pre-restore state. Investigate the extract error
in logs before re-trying.

### "archive sha256 mismatch"

The tar.gz on disk does not match what `backups` says. Two
causes:

- Disk corruption. Test with `sha256sum /data/backups/<file>`.
- Archive was swapped out of band. If you trust the on-disk file,
  update the row:
  `UPDATE backups SET sha256='<new>' WHERE filename='<file>'`.

## Notifications

### Channel shows `sent` in deliveries but nobody received

- Webhook: check the far end's logs. Argos considers `<300` as
  success regardless of the target's processing.
- Email: check the SMTP host's logs. Argos stops tracking once
  the SMTP handshake accepts the message; downstream bouncing is
  invisible.
- Telegram: the bot must be a member of the chat (group) or have
  started a conversation with the user (private chat).
- Browser push: the subscription may have silently expired. Users
  re-subscribe from the notification center.

### Deliveries queue growing

- **System health** endpoint → `workers.notification_queue_depth`.
  Growing persistently = the worker cannot keep up. Likely the
  far end is slow; lower `rate_limit_per_minute` on the channel
  so argos does not buffer events that will ultimately get
  rejected.

## Container issues

### One of the three containers constantly restarting

`docker compose logs <service> --tail=200`. Common causes:

- **argos** — DB migration failure, missing env var, port in use.
- **caddy** — Caddyfile syntax error (rare; we do not hand-edit),
  cert provisioning loop, docker volume perm issue.
- **crowdsec** — parser failure on a dirty log, LAPI DB
  corruption, wrong enrollment code.

### Docker volume permissions

Argos runs as `nobody`. If the volume was created by a root-run
container first, argos cannot read it. Fix:

```bash
docker compose down
sudo chown -R 65534:65534 /var/lib/docker/volumes/argos-edge_argos_data/_data
docker compose up -d
```

## Still stuck?

- Full logs for an incident:
  `docker compose logs --since=1h > /tmp/argos-debug.log`
- Enable debug logging temporarily:
  `ARGOS_LOG_LEVEL=debug` in `.env`, restart. Don't leave on —
  debug is chatty.
- Open an issue at
  <https://github.com/cmos486/argos-edge/issues> with: panel
  mode, versions, `.env` sanitised, the specific error, steps to
  reproduce.

## Related

- [Monitoring](monitoring.md) — what should alert you here first.
- [Tuning](tuning.md) — knobs after the fix.
- [CLI](../reference/cli.md) — `argos migrate rollback`,
  `argos restore`, `argos disable-2fa`.
