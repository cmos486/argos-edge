#!/bin/bash
# scripts/smoke/rollup-readers.sh
#
# v1.3.42.3 EFFECT smoke: the long-range readers answer from the hourly
# rollup and their numbers equal the raw rows (tolerance 0).
#
# What it checks, read-only, through /api/logs/*, /api/dashboard/traffic
# and the DB volume (sqlite3 in an alpine container, -readonly):
#   1. GET /api/logs/stats for a closed 7 d window given as from/to
#      (to = now - 2 min, so no row can land inside it after the
#      request) carries X-Argos-Path: rollup and percentile_method
#      histogram, and its total and per status-class counts equal
#      COUNT(*) over log_entries for the same window, computed through
#      the volume. Tolerance 0.
#   2. GET /api/logs/timeseries at 3600 s buckets over the same window
#      carries X-Argos-Path: rollup and the sum of its points equals
#      that total.
#   3. GET /api/logs/stats?range=1h carries X-Argos-Path: rows (a
#      window inside the hour in progress never has a closed hour).
#   4. GET /api/dashboard/traffic?range=7d and ?range=30d answer 200
#      with X-Argos-Path: rollup, percentile_method histogram, the
#      expected bucket counts (7d: 169 hourly points, 24 h of response
#      times per day; 30d: 121 six-hour points) and no bridge field
#      (detail_window / series_covers_range absent).
#   5. Reported: the time of each call.
#
# Env:
#   ARGOS_SESSION_TOKEN=<argos_session cookie value> (required)
#   [ARGOS_URL=http://127.0.0.1:9180] [ARGOS_DATA_VOLUME=argos_prod_data]
#
# Exit codes: 0 PASS, 1 FAIL, 2 precondition (token, endpoint, no rollup
# hours yet).

set -u
URL="${ARGOS_URL:-http://127.0.0.1:9180}"
TOKEN="${ARGOS_SESSION_TOKEN:-}"
VOL="${ARGOS_DATA_VOLUME:-argos_prod_data}"
H="Cookie: argos_session=${TOKEN}"
log() { echo "[rollup-readers] $*"; }

[ -n "$TOKEN" ] || { log "ARGOS_SESSION_TOKEN required" >&2; exit 2; }
command -v python3 >/dev/null || { log "python3 missing" >&2; exit 2; }
PIPE=$(curl -s -m 30 -H "$H" "$URL/api/logs/pipeline")
LAST_HOUR=$(printf '%s' "$PIPE" | python3 -c 'import json,sys; d=json.load(sys.stdin).get("rollup") or {}; print(d.get("last_hour") or "-")' 2>/dev/null)
[ -n "${LAST_HOUR:-}" ] && [ "$LAST_HOUR" != "-" ] || { log "rollup has no hours yet (pipeline endpoint: ${LAST_HOUR:-missing})" >&2; exit 2; }
log "rollup.last_hour=${LAST_HOUR}"

rc=0
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
call() { # $1 name, $2 path -> body in $TMP/$1.json, headers in $TMP/$1.h, prints seconds
  curl -s -m 120 -D "$TMP/$1.h" -o "$TMP/$1.json" -w '%{time_total}' -H "$H" "$URL$2"
}
hdr() { grep -i "^$2:" "$TMP/$1.h" | tail -1 | cut -d: -f2- | tr -d ' \r'; }
code() { head -1 "$TMP/$1.h" | awk '{print $2}'; }

# --- 1. stats over a closed 7 d window -----------------------------------
NOW_S=$(date -u +%s)
TO_S=$(( (NOW_S - 120) / 60 * 60 ))
FROM_S=$(( TO_S - 7 * 24 * 3600 ))
FROM_ISO=$(date -u -d "@$FROM_S" +%Y-%m-%dT%H:%M:%SZ); TO_ISO=$(date -u -d "@$TO_S" +%Y-%m-%dT%H:%M:%SZ)
FROM_DB=$(date -u -d "@$FROM_S" '+%Y-%m-%d %H:%M:%S +0000 UTC'); TO_DB=$(date -u -d "@$TO_S" '+%Y-%m-%d %H:%M:%S +0000 UTC')
t=$(call stats "/api/logs/stats?from=${FROM_ISO}&to=${TO_ISO}")
log "1/4 stats ${FROM_ISO}..${TO_ISO}: HTTP $(code stats) in ${t}s, X-Argos-Path=$(hdr stats X-Argos-Path)"
[ "$(code stats)" = "200" ] || { log "stats not 200" >&2; exit 2; }
read -r S_TOTAL S_METHOD S_C2 S_C3 S_C4 S_C5 S_OTHER < <(python3 -c '
import json,sys
d=json.load(open(sys.argv[1])); c=d.get("by_status_class",{})
print(d["total"], d.get("percentile_method","-"), c.get("2xx",0), c.get("3xx",0), c.get("4xx",0), c.get("5xx",0), c.get("other",0))' "$TMP/stats.json")
if [ "$(hdr stats X-Argos-Path)" = "rollup" ] && [ "$S_METHOD" = "histogram" ]; then
  log "    path rollup, percentile_method histogram: PASS"
else
  log "    expected path rollup + histogram, got $(hdr stats X-Argos-Path) / ${S_METHOD}: FAIL"; rc=1
fi
OUT=$(docker run --rm -v "${VOL}:/data:ro" alpine:3.20 sh -c "apk add -q sqlite >/dev/null 2>&1; sqlite3 -readonly /data/argos.db \"
SELECT 'total', COUNT(*) FROM log_entries WHERE timestamp >= '$FROM_DB' AND timestamp <= '$TO_DB';
SELECT 'class', CASE WHEN status >= 100 THEN status / 100 ELSE 0 END, COUNT(*) FROM log_entries WHERE timestamp >= '$FROM_DB' AND timestamp <= '$TO_DB' GROUP BY 2;\"" 2>&1)
[ -n "$OUT" ] || { log "could not read the DB volume ${VOL}" >&2; exit 2; }
read -r R_TOTAL R_C2 R_C3 R_C4 R_C5 R_OTHER < <(printf '%s\n' "$OUT" | python3 -c '
import sys
total=0; c={}
for l in sys.stdin:
    p=l.strip().split("|")
    if p[0]=="total": total=int(p[1])
    elif p[0]=="class": c[int(p[1])]=int(p[2])
other=total-sum(c.get(k,0) for k in (2,3,4,5))
print(total, c.get(2,0), c.get(3,0), c.get(4,0), c.get(5,0), other)')
log "    api total=${S_TOTAL} 2xx=${S_C2} 3xx=${S_C3} 4xx=${S_C4} 5xx=${S_C5} other=${S_OTHER}"
log "    rows total=${R_TOTAL} 2xx=${R_C2} 3xx=${R_C3} 4xx=${R_C4} 5xx=${R_C5} other=${R_OTHER}"
if [ "$S_TOTAL" = "$R_TOTAL" ] && [ "$S_C2" = "$R_C2" ] && [ "$S_C3" = "$R_C3" ] && [ "$S_C4" = "$R_C4" ] && [ "$S_C5" = "$R_C5" ] && [ "$S_OTHER" = "$R_OTHER" ]; then
  log "    stats equal the rows (tolerance 0): PASS"
else
  log "    stats differ from the rows: FAIL"; rc=1
fi

# --- 2. timeseries over the same window ---------------------------------
t=$(call ts "/api/logs/timeseries?from=${FROM_ISO}&to=${TO_ISO}&bucket_seconds=3600")
TS_SUM=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sum(p["total"] for p in d.get("points",[])), len(d.get("points",[])))' "$TMP/ts.json")
log "2/4 timeseries: HTTP $(code ts) in ${t}s, X-Argos-Path=$(hdr ts X-Argos-Path), points sum / n = ${TS_SUM}"
if [ "$(hdr ts X-Argos-Path)" = "rollup" ] && [ "${TS_SUM%% *}" = "$R_TOTAL" ]; then
  log "    timeseries sum equals the rows: PASS"
else
  log "    timeseries path or sum wrong: FAIL"; rc=1
fi

# --- 3. a window inside the hour in progress stays on rows --------------
t=$(call short "/api/logs/stats?range=1h")
log "3/4 stats range=1h: HTTP $(code short) in ${t}s, X-Argos-Path=$(hdr short X-Argos-Path)"
if [ "$(hdr short X-Argos-Path)" = "rows" ]; then log "    rows path: PASS"; else log "    expected rows: FAIL"; rc=1; fi

# --- 4. dashboard traffic 7d and 30d ------------------------------------
for R in 7d 30d; do
  t=$(call "traffic$R" "/api/dashboard/traffic?range=$R")
  read -r NB NRT METHOD BRIDGE < <(python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
bridge="detail_window" in d or "series_covers_range" in d
print(len(d.get("timeseries",[])), len(d.get("response_times",[])), d.get("percentile_method","-"), "yes" if bridge else "no")' "$TMP/traffic$R.json")
  log "4/4 traffic range=$R: HTTP $(code "traffic$R") in ${t}s, X-Argos-Path=$(hdr "traffic$R" X-Argos-Path) X-Argos-Cache=$(hdr "traffic$R" X-Argos-Cache), buckets=${NB} response_times=${NRT} method=${METHOD} bridge_fields=${BRIDGE}"
  want=169; [ "$R" = "30d" ] && want=121
  if [ "$(code "traffic$R")" = "200" ] && [ "$(hdr "traffic$R" X-Argos-Path)" = "rollup" ] && [ "$METHOD" = "histogram" ] && [ "$BRIDGE" = "no" ] && [ "$NB" = "$want" ]; then
    log "    $R: PASS"
  else
    log "    $R: FAIL (want 200, rollup, histogram, no bridge fields, ${want} buckets)"; rc=1
  fi
done

[ "$rc" -eq 0 ] && log "PASS" || log "FAIL"
exit "$rc"
