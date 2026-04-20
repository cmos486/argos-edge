# Monitoring

What to watch continuously on a live panel, what to alert on, and
what to ignore.

## The two-screen split

Once the panel is configured and serving traffic, operator
attention splits across two surfaces:

- **Panel UI** — Dashboard, Security overview, Threats, Logs.
  Manual polling, mostly during investigation.
- **External monitor** — uptime probes + webhook / email
  notifications. Passive, fires on conditions.

Both matter. The panel UI is where you diagnose; the external
monitor is what pages you at 03:00 when something breaks.

## What to alert on (notification rules)

The minimum rule set an internet-exposed panel should have wired
from day one. Wire each as a **Notifications → Rule** pointing at
your chosen channel (webhook to Slack / Discord, email, Telegram):

| Event                     | Reason it matters | Throttle recommendation |
|---------------------------|-------------------|-------------------------|
| `backup_failed`           | Silent backup failure erodes recoverability week by week. | 0 (every failure) |
| `cert_renewal_failed`     | 90 days from failure to cert expiry is not enough if you do not find out. | 0 |
| `cert_expiring_soon`      | Last-line fallback if the renewal path is broken. | 86400 (once per day) |
| `crowdsec_down`           | Argos keeps serving, but WAF + bouncer degrade to pass-through for community decisions. | 300 (5 min) |
| `target_unhealthy`        | You want to know before users notice. | 300 |
| `health_degraded`         | /system/health flagged a subsystem. | 600 |
| `waf_attack_burst`        | Real-time awareness of active attacks. | 300 |

Optional depending on noise tolerance:

- `login_failed` — noisy on an internet-exposed panel login but
  valuable when scoped to the local admin only.
- `rate_limit_triggered` — useful if you set rate limits that are
  rarely hit (a sudden hit signals unusual load).
- `config_change` — a paper-trail copy of the audit log. Wire
  only if you have a second admin and want change notifications.

Full event catalog: [Notifications](../features/notifications.md).

## External uptime probe

Wire an uptime check against `GET /healthz`. Returns `200 OK` with
body `ok` when the panel's HTTP layer is alive. It does NOT probe
deeper subsystems — for that use `GET /api/system/health` with an
authed request.

Recommended:

- **30-60 s interval** against `/healthz` (unauthed, cheap).
- **5-15 min interval** against `/api/system/health` with a
  session cookie. Alert on:
    - `memory.Alloc > 500_000_000` (half a GB; normal is single-
      digit MB).
    - `workers.notification_queue_dropped > 0` (non-zero =
      events lost).
    - `scheduler.last_backup_status != "ok"`.
    - `db.wal_size_bytes > 500_000_000` (WAL runaway suggests a
      long-running reader or a crashed writer).

The panel does not have a built-in Prometheus exporter; scrape
the JSON and shape it yourself if you use Prometheus/Grafana.

## Dashboard first-pass (every morning, 30 s)

In this order:

1. **Traffic** card — did yesterday's volume look sane? Spikes
   are either legitimate (a viral link) or attack (scanners). The
   Security card disambiguates.
2. **Security** card — blocked counts over the last 24 h. Zero
   is suspicious on an internet-facing panel; a few tens per day
   is normal.
3. **Health** card — queue depth, goroutine count, last backup.
   Anomalies jump out.
4. **Attacks by country** map — world map of offending IPs. One
   country heavily dominating means you probably want a CrowdSec
   scenario tuned or a per-country rule.

## When the phone wakes you up

Triage order for each alert type:

### backup_failed

- **Logs tab** filter `source = audit AND message = backup_failed`.
  Error message is in the row's `raw` JSON.
- Common causes: disk full on `argos_data` volume, permission
  issue on `/data/backups/`, `VACUUM INTO` failed because the
  disk is full or the temp dir is not writable.
- Fix, then trigger a manual backup to confirm.

### cert_renewal_failed

- **Certs tab**: find the affected host. The row shows the
  last-check timestamp + issuer state.
- `docker compose logs caddy | grep acme` for the ACME error.
- Usual cause: DNS changed / port 80 blocked / rate limit at
  Let's Encrypt.

### crowdsec_down

- `docker compose logs crowdsec --tail=100`.
- If the container is up but the panel can't reach it: check
  `crowdsec.lapi_url` setting.
- If the container is crashed: inspect for storage corruption
  (`/var/lib/crowdsec/data` volume).
- Safe to ignore for a few minutes; Caddy's bouncer cache carries
  decisions forward.

### target_unhealthy

- **Target Groups → *group***. The failing target shows red.
- Check the upstream's own health endpoint from inside argos:
  `docker compose exec argos wget -qO- http://10.0.0.42:8080/healthz`.
- Root cause is usually in the upstream, not argos.

### waf_attack_burst

- **AppSec tab**: the loudest rule IDs aggregated.
- **Logs** filter `source = waf_audit AND waf_severity IN
  ('CRITICAL', 'ERROR')` sorted by `waf_anomaly_score DESC`.
- See [Respond to an attack](../workflows/respond-to-attack.md)
  for the full playbook.

## What to ignore

Signals that look scary but usually are not:

- **Individual WAF hits at severity NOTICE/WARNING**. Low-severity
  rules fire on legit-but-unusual traffic all the time. Alert on
  *bursts*, not individual hits.
- **Occasional 4xx spikes on new paths**. Most of the time it is
  a scanner. If CrowdSec is on, it will handle those silently.
- **Dropped notification queue rows during a brief outage**. The
  worker drops events when saturated to keep the request path
  unblocked. Recovery on next run. Only alert if drops are
  continuous.

## Audit log as observability

Every mutation (hosts / target groups / rules / security /
notifications / backups / config) lands in `log_entries` with
`source = audit`. Useful queries:

- `source = audit AND message LIKE 'login%'` -- login history +
  failed attempts over any time window.
- `source = audit AND message LIKE 'oidc_%'` -- OIDC flow
  outcomes, useful when an IdP misbehaves.
- `source = audit AND message LIKE '%delete%'` -- deletion
  history. Handy for "did someone delete this host and when".

All audit rows include `remote_ip` and `user_agent` since the
Fase 2 security sweep.

## Related

- [Observability](../features/observability.md) — the feature
  side: Dashboard, Logs, GeoIP.
- [Notifications](../features/notifications.md) — channel + rule
  setup.
- [Troubleshooting](troubleshooting.md) — what to do when an alert
  fires.
- [Tuning](tuning.md) — knobs you have at day two.
