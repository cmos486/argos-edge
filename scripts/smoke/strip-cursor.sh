#!/bin/bash
# scripts/smoke/strip-cursor.sh
#
# v1.3.40.4 EFFECT smoke: the raw strip walks the (timestamp, id)
# cursor from the cursor, not from the oldest row (strike 14).
#
# What it does: lowers logs.retention.raw_hours by STRIP_HOURS (default
# 6, so about 6 h of access rows lose their raw), POSTs a forced purge,
# samples GET /api/hosts every 100 ms and the panel's CPU (docker
# stats) every 2 s until the panel logs "retention purge done", then
# restores raw_hours.
#
# EFFECT verified:
#   1. raw_stripped in the purge log line > 0 (the strip ran).
#   2. Panel CPU during the strip: max sample <= MAX_CPU_PCT (default
#      10). With the v1.3.40.2 OR predicate the panel sat at 50-60 %
#      because every 200-row batch rescanned the index from the oldest
#      row; with both bounds in the range term it is 2-5 %.
#   3. Reported, not gated here: p50 / p99 / max of /api/hosts during
#      the strip. On a single connection the p99 stays above 50 ms
#      (writer busy per batch and per checkpoint); that gate belongs to
#      the read pool (v1.3.41.0, read-pool.sh).
#
# Env:
#   ARGOS_SESSION_TOKEN=<argos_session cookie value> (required)
#   [ARGOS_URL=http://127.0.0.1:9180] [ARGOS_PANEL_CONTAINER=argos-prod-panel]
#   [STRIP_HOURS=6] [MAX_CPU_PCT=10] [CAP_S=900]
#
# Exit codes: 0 PASS, 1 FAIL (an EFFECT check failed), 2 precondition
# (no token, non-200, purge never finished; raw_hours restored anyway).

set -u
URL="${ARGOS_URL:-http://127.0.0.1:9180}"
TOKEN="${ARGOS_SESSION_TOKEN:-}"
PANEL="${ARGOS_PANEL_CONTAINER:-argos-prod-panel}"
STRIP_HOURS="${STRIP_HOURS:-6}"
MAX_CPU_PCT="${MAX_CPU_PCT:-10}"
CAP_S="${CAP_S:-900}"
H="Cookie: argos_session=${TOKEN}"
log() { echo "[strip-cursor] $*"; }

[ -n "$TOKEN" ] || { log "ARGOS_SESSION_TOKEN required" >&2; exit 2; }
command -v python3 >/dev/null || { log "python3 missing" >&2; exit 2; }
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$H" "$URL/api/auth/me")
[ "$code" = "200" ] || { log "/api/auth/me ${code}" >&2; exit 2; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
pipeline=$(curl -s -H "$H" "$URL/api/logs/pipeline")
RAW_HOURS=$(printf '%s' "$pipeline" | python3 -c 'import json,sys; print(json.load(sys.stdin)["retention"]["raw_hours"])')
[ -n "$RAW_HOURS" ] || { log "could not read raw_hours" >&2; exit 2; }
NEW_HOURS=$(( RAW_HOURS - STRIP_HOURS ))
[ "$NEW_HOURS" -ge 1 ] || { log "raw_hours ${RAW_HOURS} too small to strip ${STRIP_HOURS} h" >&2; exit 2; }

restore() {
  curl -s -o /dev/null -X PUT -H "$H" -H 'Content-Type: application/json' \
    -d "{\"value\":\"${RAW_HOURS}\"}" "$URL/api/settings/logs.retention.raw_hours"
  log "raw_hours restored to ${RAW_HOURS}"
}

log "raw_hours ${RAW_HOURS} -> ${NEW_HOURS} for the run (about ${STRIP_HOURS} h of access rows to strip)"
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$H" -H 'Content-Type: application/json' \
  -d "{\"value\":\"${NEW_HOURS}\"}" "$URL/api/settings/logs.retention.raw_hours")
[ "$code" = "200" ] || { log "PUT raw_hours ${code}" >&2; exit 2; }

START_MARK=$(date -u +%Y-%m-%dT%H:%M:%S)
: > "$TMP/lat"; : > "$TMP/cpu"; : > "$TMP/stop"
rm -f "$TMP/stop"
( while [ ! -f "$TMP/stop" ]; do
    curl -s -m 70 -o /dev/null -w '%{time_total}\n' -H "$H" "$URL/api/hosts" >> "$TMP/lat"; sleep 0.1
  done ) &
( while [ ! -f "$TMP/stop" ]; do
    docker stats --no-stream --format '{{.CPUPerc}}' "$PANEL" 2>/dev/null | tr -d '%' >> "$TMP/cpu"; sleep 2
  done ) &
sleep 1
curl -s -m "$CAP_S" -o /dev/null -w 'purge %{http_code} in %{time_total}s\n' -X POST -H "$H" "$URL/api/logs/purge" | sed 's/^/[strip-cursor] /'
DONE=""
for _ in $(seq 1 "$CAP_S"); do
  LINE=$(docker logs "$PANEL" --since "${START_MARK}Z" 2>&1 | grep 'retention purge done' | tail -1)
  [ -n "$LINE" ] && { DONE=1; break; }
  sleep 1
done
touch "$TMP/stop"; wait
restore
[ -n "$DONE" ] || { log "purge did not log done within ${CAP_S}s" >&2; exit 2; }

STRIPPED=$(printf '%s' "$LINE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("raw_stripped",0))')
read -r P50 P99 MAX N < <(python3 -c "
import sys
v=sorted(float(x)*1000 for x in open(sys.argv[1]) if x.strip())
q=lambda p: v[min(len(v)-1,int(round(p*(len(v)-1))))] if v else 0
print('%.1f %.1f %.1f %d' % (q(.5), q(.99), v[-1] if v else 0, len(v)))" "$TMP/lat")
CPU_MAX=$(sort -n "$TMP/cpu" | tail -1); CPU_MAX=${CPU_MAX:-0}
CPU_MED=$(sort -n "$TMP/cpu" | awk '{a[NR]=$1} END {print (NR? a[int((NR+1)/2)] : 0)}')

rc=0
log "raw_stripped=${STRIPPED}"
if [ "${STRIPPED:-0}" -gt 0 ]; then log "strip ran: PASS"; else log "nothing stripped: FAIL"; rc=1; fi
log "panel cpu during strip: median ${CPU_MED} %, max ${CPU_MAX} % (gate <= ${MAX_CPU_PCT} %)"
if python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)" "$CPU_MAX" "$MAX_CPU_PCT"; then
  log "cpu: PASS"
else
  log "cpu: FAIL"; rc=1
fi
log "/api/hosts during strip: n=${N} p50 ${P50} ms, p99 ${P99} ms, max ${MAX} ms (reported; gated by read-pool.sh from v1.3.41.0)"
[ $rc -eq 0 ] && log "PASS" || log "FAIL"
exit $rc
