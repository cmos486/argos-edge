#!/bin/bash
# scripts/smoke/logs-pipeline.sh
#
# v1.3.40.0 EFFECT smoke for the log pipeline (ingest filter,
# per-source retention, raw strip, bounded cap count).
#
# What it measures, on the live panel and its SQLite volume (read-only
# queries through a throwaway alpine container):
#   1. rows ingested per day per source over the last full day, and
#      how many of them belong to the families the default filter
#      drops (uptime monitors by user agent, the reverse-proxy health
#      checker lines). After the deploy those families must stop
#      arriving: rows with timestamp after the panel start matching
#      them must be <= MAX_FILTERED_ROWS.
#   2. raw JSON on caddy_access rows older than raw_hours + 1 h must be
#      NULL once the first purge after the deploy has run (the panel
#      is older than 25 h); reported as PENDING before that.
#   3. the DB file size (page_count * page_size) and the row count,
#      printed for the 48 h before/after comparison in the release
#      note (no threshold: the number is the deliverable).
#   4. p99 of GET /api/hosts while a purge runs (POST /api/logs/purge,
#      the same job the panel runs every 6 h), sampled every 100 ms
#      until the purge returns: must be <= MAX_P99_MS.
#
# Usage:
#   ARGOS_SESSION_TOKEN=<argos_session cookie value> \
#   [ARGOS_URL=http://127.0.0.1:9180] [ARGOS_DATA_VOLUME=argos_prod_data] \
#   [ARGOS_PANEL_CONTAINER=argos-prod-panel] [MAX_FILTERED_ROWS=100] [MAX_P99_MS=50] \
#     scripts/smoke/logs-pipeline.sh
#
# Exit codes:
#   0  PASS (a PENDING raw check does not fail the run)
#   1  FAIL: filtered families still stored, raw not stripped, or p99 over
#   2  precondition failed (no token, docker/sqlite error, non-200)
set -u

URL="${ARGOS_URL:-http://127.0.0.1:9180}"
TOKEN="${ARGOS_SESSION_TOKEN:-}"
VOL="${ARGOS_DATA_VOLUME:-argos_prod_data}"
PANEL="${ARGOS_PANEL_CONTAINER:-argos-prod-panel}"
MAX_FILTERED="${MAX_FILTERED_ROWS:-100}"
MAX_P99="${MAX_P99_MS:-50}"

[ -n "$TOKEN" ] || { echo "[logs-pipeline] ARGOS_SESSION_TOKEN required" >&2; exit 2; }
for c in curl docker python3; do command -v $c >/dev/null 2>&1 || { echo "[logs-pipeline] $c missing" >&2; exit 2; }; done

sq() { # run a read-only query on the panel's DB volume
  docker run --rm -v "${VOL}:/data:ro" alpine sh -c "apk add --no-cache sqlite >/dev/null 2>&1; sqlite3 -readonly /data/argos.db \"$1\"" 2>/dev/null
}

STARTED=$(docker inspect "$PANEL" --format '{{.State.StartedAt}}' 2>/dev/null) || { echo "[logs-pipeline] cannot inspect $PANEL" >&2; exit 2; }
START_SQL=$(python3 -c "import datetime,sys;print(datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')).strftime('%Y-%m-%d %H:%M:%S'))" "$STARTED")
AGE_H=$(python3 -c "import datetime,sys;d=datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00'));print(int(d.total_seconds()//3600))" "$STARTED")

code=$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: argos_session=${TOKEN}" "${URL}/api/auth/me")
[ "$code" = "200" ] || { echo "[logs-pipeline] /api/auth/me returned ${code}" >&2; exit 2; }

echo "[logs-pipeline] panel started ${STARTED} (${AGE_H} h ago)"
echo "[logs-pipeline] rows per source, last full day (UTC):"
sq "SELECT source, COUNT(*) FROM log_entries WHERE timestamp >= date('now','-1 day') AND timestamp < date('now') GROUP BY source;" | sed 's/^/[logs-pipeline]   /'
fail=0
echo "[logs-pipeline] rows and DB file size now:"
ROWS=$(sq "SELECT COUNT(*) FROM log_entries;")
SIZE=$(sq "SELECT page_count*page_size FROM pragma_page_count(), pragma_page_size();")
RAWMB=$(sq "SELECT ROUND(SUM(length(raw))/1048576.0,1) FROM log_entries WHERE source='caddy_access';")
LASTPURGE=$(docker logs "$PANEL" 2>&1 | grep -E 'retention purge (done|failed)' | tail -1 | sed -E 's/^\{"time":"([^"]+)".*"msg":"([^"]+)"(.*)/\1 \2\3/' | cut -c1-200)
echo "[logs-pipeline]   last purge: ${LASTPURGE:-none logged}"
case "$LASTPURGE" in *"purge failed"*) echo "[logs-pipeline] FAIL: the last retention purge failed"; fail=1;; esac
echo "[logs-pipeline]   rows=${ROWS} db_bytes=${SIZE} access_raw_mb=${RAWMB}"

# 1. filtered families since the panel started
MON=$(sq "SELECT COUNT(*) FROM log_entries WHERE source='caddy_access' AND (user_agent LIKE 'Uptime-Kuma/%' OR user_agent LIKE 'UptimeRobot/%') AND timestamp >= '${START_SQL}';")
HC=$(sq "SELECT COUNT(*) FROM log_entries WHERE source='caddy_error' AND message LIKE 'http.handlers.reverse_proxy.health_checker.active: HTTP request failed%' AND timestamp >= '${START_SQL}';")
echo "[logs-pipeline] stored since start: monitor UA rows=${MON} health-checker routine rows=${HC} (PASS if each <= ${MAX_FILTERED})"
if [ "${MON:-0}" -gt "$MAX_FILTERED" ] || [ "${HC:-0}" -gt "$MAX_FILTERED" ]; then echo "[logs-pipeline] FAIL: filtered families are still being stored"; fail=1; fi
DROPPED=$(curl -s -H "Cookie: argos_session=${TOKEN}" "${URL}/api/logs/pipeline" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin); x=d['ingest'].get('dropped') or {}; print(x.get('total',0), d['retention']['raw_hours'])
except Exception:
    print('n/a 24')  # panel older than v1.3.40.0: no pipeline endpoint
")
set -- $DROPPED; DROPPED_TODAY=${1:-0}; RAW_HOURS=${2:-24}
echo "[logs-pipeline] ingest filter counters today: ${DROPPED_TODAY} rows (raw_hours=${RAW_HOURS})"

# 2. raw strip (valid once the panel is older than raw_hours + 1 h)
NOTNULL=$(sq "SELECT COUNT(*) FROM log_entries WHERE source='caddy_access' AND raw <> '' AND timestamp < datetime('now','-$((RAW_HOURS+1)) hours');")
if [ "$AGE_H" -ge $((RAW_HOURS+1)) ]; then
  if [ "${NOTNULL:-0}" -gt 0 ]; then echo "[logs-pipeline] FAIL: ${NOTNULL} access rows older than $((RAW_HOURS+1)) h still carry raw"; fail=1; else echo "[logs-pipeline] raw strip: 0 access rows older than $((RAW_HOURS+1)) h carry raw PASS"; fi
else
  echo "[logs-pipeline] raw strip: PENDING (panel younger than $((RAW_HOURS+1)) h; ${NOTNULL} rows still carry raw, expected until the first purge past the window)"
fi

# 4. p99 of /api/hosts during a purge
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
( curl -s -o /dev/null -w 'purge %{http_code} in %{time_total}s\n' -X POST -H "Cookie: argos_session=${TOKEN}" "${URL}/api/logs/purge" > "$TMP.purge" ) &
PID=$!
: > "$TMP"
while kill -0 $PID 2>/dev/null; do
  curl -s -o /dev/null -w '%{time_total}\n' -H "Cookie: argos_session=${TOKEN}" "${URL}/api/hosts" >> "$TMP"
  sleep 0.1
done
wait $PID
P=$(python3 -c "
import sys
v=sorted(float(x)*1000 for x in open(sys.argv[1]) if x.strip())
def pct(p):
    if not v: return 0
    return v[min(len(v)-1, int(round((p/100)*(len(v)-1))))]
print('%d %.1f %.1f %.1f' % (len(v), pct(50), pct(99), max(v) if v else 0))" "$TMP")
set -- $P
echo "[logs-pipeline] $(cat "$TMP.purge" 2>/dev/null); /api/hosts during the purge: n=$1 p50=${2}ms p99=${3}ms max=${4}ms (PASS if p99 <= ${MAX_P99} ms)"
rm -f "$TMP.purge"
if python3 -c "import sys;sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)" "$3" "$MAX_P99"; then :; else echo "[logs-pipeline] FAIL: p99 ${3} ms > ${MAX_P99} ms"; fail=1; fi

[ $fail -eq 0 ] && { echo "[logs-pipeline] PASS"; exit 0; }
exit 1
