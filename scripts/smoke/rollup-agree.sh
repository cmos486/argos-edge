#!/bin/bash
# scripts/smoke/rollup-agree.sh
#
# v1.3.42.0 EFFECT smoke: the hourly rollup (log_hourly) agrees with the
# raw rows (log_entries) for a closed hour, tolerance 0, and the job is
# keeping up.
#
# What it checks, read-only, through the DB volume (sqlite3 in an
# alpine container, -readonly) and /api/logs/pipeline:
#   1. rollup.last_hour in the pipeline endpoint is at most
#      MAX_LAG_HOURS (default 2) behind the last closed UTC hour (the
#      HH:02 job ran).
#   2. For the newest closed hour at least 3 h old that the rollup has:
#      COUNT(*) and SUM(size_bytes) over log_entries equal SUM(requests)
#      and SUM(bytes_out) over log_hourly, and the per status-class
#      counts match row by row. Tolerance 0.
#   3. rollup.drift persisted by the 6 h ticker is "0" (reported; a
#      non-zero value with the numbers is a FAIL).
#
# Env:
#   ARGOS_SESSION_TOKEN=<argos_session cookie value> (required)
#   [ARGOS_URL=http://127.0.0.1:9180] [ARGOS_DATA_VOLUME=argos_prod_data]
#   [MAX_LAG_HOURS=2]
#
# Exit codes: 0 PASS, 1 FAIL, 2 precondition (token, endpoint, no rollup rows yet).

set -u
URL="${ARGOS_URL:-http://127.0.0.1:9180}"
TOKEN="${ARGOS_SESSION_TOKEN:-}"
VOL="${ARGOS_DATA_VOLUME:-argos_prod_data}"
MAX_LAG_HOURS="${MAX_LAG_HOURS:-2}"
H="Cookie: argos_session=${TOKEN}"
log() { echo "[rollup-agree] $*"; }

[ -n "$TOKEN" ] || { log "ARGOS_SESSION_TOKEN required" >&2; exit 2; }
command -v python3 >/dev/null || { log "python3 missing" >&2; exit 2; }
PIPE=$(curl -s -m 30 -H "$H" "$URL/api/logs/pipeline")
read -r LAST_HOUR DRIFT DRIFT_AT < <(printf '%s' "$PIPE" | python3 -c '
import json,sys
d=json.load(sys.stdin).get("rollup") or {}
print(d.get("last_hour") or "-", (d.get("drift") if d.get("drift") not in (None,"") else "-").replace(" ","_"), d.get("drift_checked_at") or "-")' 2>/dev/null)
[ -n "${LAST_HOUR:-}" ] || { log "pipeline endpoint has no rollup block (pre-v1.3.42.0?)" >&2; exit 2; }
[ "$LAST_HOUR" != "-" ] || { log "rollup has no hours yet (boot backfill pending?)" >&2; exit 2; }

rc=0
NOW_HOUR=$(date -u +%Y-%m-%dT%H:00:00Z)
LAG=$(python3 -c "
from datetime import datetime,timezone
last=datetime.strptime('$LAST_HOUR','%Y-%m-%dT%H:%M:%SZ'); now=datetime.strptime('$NOW_HOUR','%Y-%m-%dT%H:%M:%SZ')
print(int((now-last).total_seconds()//3600)-1)")
log "rollup.last_hour=${LAST_HOUR} (lag ${LAG} h behind the last closed hour; max ${MAX_LAG_HOURS})"
if [ "$LAG" -le "$MAX_LAG_HOURS" ]; then log "job keeps up: PASS"; else log "job behind: FAIL"; rc=1; fi

# Newest closed hour at least 3 h old, as the driver stores it.
HOUR=$(python3 -c "
from datetime import datetime,timedelta
last=datetime.strptime('$LAST_HOUR','%Y-%m-%dT%H:%M:%SZ'); now=datetime.strptime('$NOW_HOUR','%Y-%m-%dT%H:%M:%SZ')
h=min(last, now-timedelta(hours=3)); print(h.strftime('%Y-%m-%d %H:00:00 +0000 UTC'))")
NEXT=$(python3 -c "
from datetime import datetime,timedelta
h=datetime.strptime('$HOUR','%Y-%m-%d %H:%M:%S +0000 UTC'); print((h+timedelta(hours=1)).strftime('%Y-%m-%d %H:00:00 +0000 UTC'))")
OUT=$(docker run --rm -v "${VOL}:/data:ro" alpine:3.20 sh -c "apk add -q sqlite >/dev/null 2>&1; sqlite3 -readonly /data/argos.db \"
SELECT 'raw', COUNT(*), COALESCE(SUM(size_bytes),0) FROM log_entries WHERE timestamp >= '$HOUR' AND timestamp < '$NEXT';
SELECT 'rollup', COALESCE(SUM(requests),0), COALESCE(SUM(bytes_out),0) FROM log_hourly WHERE hour = '$HOUR';
SELECT 'rawclass', CASE WHEN status >= 100 THEN status / 100 ELSE 0 END, COUNT(*) FROM log_entries WHERE timestamp >= '$HOUR' AND timestamp < '$NEXT' GROUP BY 2;
SELECT 'rollclass', status_class, SUM(requests) FROM log_hourly WHERE hour = '$HOUR' GROUP BY 2;\"" 2>&1)
[ -n "$OUT" ] || { log "could not read the DB volume ${VOL}" >&2; exit 2; }
VERDICT=$(printf '%s\n' "$OUT" | python3 -c '
import sys
raw=roll=None; rc={}; lc={}
for l in sys.stdin:
    p=l.strip().split("|")
    if p[0]=="raw": raw=(int(p[1]),int(p[2]))
    elif p[0]=="rollup": roll=(int(p[1]),int(p[2]))
    elif p[0]=="rawclass": rc[int(p[1])]=int(p[2])
    elif p[0]=="rollclass": lc[int(p[1])]=int(p[2])
ok = raw==roll and rc==lc
print("PASS" if ok else "FAIL", raw, roll, sorted(rc.items()), sorted(lc.items()))')
log "hour ${HOUR}: raw (rows, bytes) vs rollup, classes raw vs rollup -> ${VERDICT#* }"
case "$VERDICT" in PASS*) log "rollup agrees with raw (tolerance 0): PASS" ;; *) log "rollup diverges: FAIL"; rc=1 ;; esac

log "ticker drift verdict: ${DRIFT} (checked ${DRIFT_AT})"
if [ "$DRIFT" != "0" ] && [ "$DRIFT" != "-" ]; then log "ticker recorded drift: FAIL"; rc=1; fi
[ $rc -eq 0 ] && log "PASS" || log "FAIL"
exit $rc
