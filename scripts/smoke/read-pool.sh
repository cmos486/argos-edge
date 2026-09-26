#!/bin/bash
# scripts/smoke/read-pool.sh
#
# v1.3.41.0 EFFECT smoke: GET handlers read through the read-only
# pool, so a purge, a strip, an export or the pinned dashboard refresh
# on the writer connection no longer queues them.
#
# Samples GET /api/hosts every 100 ms from the host during four
# operations and gates the p99 of each (MAX_P99_MS, default 50):
#
#   0. the panel log says which mode is running ("read pool enabled" /
#      "read pool disabled by ARGOS_READ_POOL=0"); EXPECT_POOL (default
#      1) says which one this run expects. Precondition, not a gate.
#   1. idle for IDLE_S (default 120): the pinned 24 h refresh runs
#      every 24 s on the dashboard cache.
#   2. forced strip: raw_hours lowered by STRIP_HOURS (default 6),
#      POST /api/logs/purge, until "retention purge done"; raw_hours
#      restored. raw_stripped must be > 0.
#   3. CSV export of the newest 24 h of access rows, EXPORT_RUNS times
#      (default 3) back to back; one p99 over all samples of the three
#      runs (about 165 samples), not the worst sample of one pass.
#   4. cap purge: logs.max_entries set to (rows - CAP_PURGE_ROWS) so the
#      purge runs COUNT(*) and deletes CAP_PURGE_ROWS oldest rows;
#      max_entries restored. Default 0 = skipped: no data is deleted
#      to pass a gate on prod (operator rule, 2026-09-26); the demo
#      runs it with CAP_PURGE_ROWS=50000 on the dense seed.
#
# IO_PRESSURE=1 runs a dd loop (256 MB files, O_DIRECT + fsync) on
# IO_DIR (default the script's temp dir, same disk) for the whole run,
# because on a quiet disk the single-connection panel passes these
# gates too: the stall the pool removes is the checkpoint fsync under
# IO pressure. Demo only (operator rule, 2026-09-26): prod runs
# without dd and the IO gate is covered by the dense demo.
#
# If a gate FAILs on prod the kill-switch is ARGOS_READ_POOL=0 in
# ~/argos-prod/.env + make deploy-prod (v1.3.40.4 behaviour, no image
# rollback). This script never changes that flag.
#
# Env:
#   ARGOS_SESSION_TOKEN=<argos_session cookie value> (required)
#   [ARGOS_URL=http://127.0.0.1:9180] [ARGOS_PANEL_CONTAINER=argos-prod-panel]
#   [MAX_P99_MS=50] [IDLE_S=120] [STRIP_HOURS=6] [EXPORT_RUNS=3]
#   [CAP_PURGE_ROWS=0] [IO_PRESSURE=0] [IO_DIR=<tmp>] [EXPECT_POOL=1] [CAP_S=1500]
#   [KEEP_DIR=<dir>]  copy the per-gate latency samples (idle, strip,
#                     export, cap; seconds per line) there before exit,
#                     so a FAIL can be placed in time after the run
#
# Exit codes: 0 PASS, 1 FAIL (a gate over MAX_P99_MS or a strip that
# stripped nothing), 2 precondition (token, mode mismatch, purge never
# finished; settings restored anyway).

set -u
URL="${ARGOS_URL:-http://127.0.0.1:9180}"
TOKEN="${ARGOS_SESSION_TOKEN:-}"
PANEL="${ARGOS_PANEL_CONTAINER:-argos-prod-panel}"
MAX_P99_MS="${MAX_P99_MS:-50}"
IDLE_S="${IDLE_S:-120}"
STRIP_HOURS="${STRIP_HOURS:-6}"
EXPORT_RUNS="${EXPORT_RUNS:-3}"
CAP_PURGE_ROWS="${CAP_PURGE_ROWS:-0}"
IO_PRESSURE="${IO_PRESSURE:-0}"
EXPECT_POOL="${EXPECT_POOL:-1}"
CAP_S="${CAP_S:-1500}"
H="Cookie: argos_session=${TOKEN}"
log() { echo "[read-pool] $*"; }

[ -n "$TOKEN" ] || { log "ARGOS_SESSION_TOKEN required" >&2; exit 2; }
command -v python3 >/dev/null || { log "python3 missing" >&2; exit 2; }
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$H" "$URL/api/auth/me")
[ "$code" = "200" ] || { log "/api/auth/me ${code}" >&2; exit 2; }

TMP=$(mktemp -d); IO_DIR="${IO_DIR:-$TMP}"
RC=0; RAW_HOURS=""; MAX_ENTRIES=""
cleanup() {
  touch "$TMP/stop"
  [ -n "$RAW_HOURS" ] && curl -s -o /dev/null -X PUT -H "$H" -H 'Content-Type: application/json' \
    -d "{\"value\":\"${RAW_HOURS}\"}" "$URL/api/settings/logs.retention.raw_hours"
  [ -n "$MAX_ENTRIES" ] && curl -s -o /dev/null -X PUT -H "$H" -H 'Content-Type: application/json' \
    -d "{\"value\":\"${MAX_ENTRIES}\"}" "$URL/api/settings/logs.max_entries"
  wait 2>/dev/null
  rm -f "$IO_DIR/argos-io-pressure"
  if [ -n "${KEEP_DIR:-}" ]; then
    mkdir -p "$KEEP_DIR" && for f in idle strip export cap; do
      [ -f "$TMP/$f" ] && cp "$TMP/$f" "$KEEP_DIR/read-pool-$f.lat"
    done
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

# --- 0. mode ----------------------------------------------------------
MODE=$(docker logs "$PANEL" 2>&1 | grep -oE 'read pool (enabled|disabled by ARGOS_READ_POOL=0)' | tail -1)
log "panel log: ${MODE:-no read pool line (pre-v1.3.41.0 image?)}"
case "${EXPECT_POOL}:${MODE}" in
  1:"read pool enabled"|0:"read pool disabled by ARGOS_READ_POOL=0") ;;
  *) log "mode does not match EXPECT_POOL=${EXPECT_POOL}" >&2; exit 2 ;;
esac

pipeline=$(curl -s -H "$H" "$URL/api/logs/pipeline")
RAW_HOURS=$(printf '%s' "$pipeline" | python3 -c 'import json,sys; print(json.load(sys.stdin)["retention"]["raw_hours"])')
MAX_ENTRIES=$(printf '%s' "$pipeline" | python3 -c 'import json,sys; print(json.load(sys.stdin)["retention"]["max_entries"])')
ROWS=$(printf '%s' "$pipeline" | python3 -c 'import json,sys; print(sum(json.load(sys.stdin)["current"]["rows_by_source"].values()))')
[ -n "$RAW_HOURS" ] && [ -n "$MAX_ENTRIES" ] || { log "could not read retention settings" >&2; exit 2; }
log "rows=${ROWS} raw_hours=${RAW_HOURS} max_entries=${MAX_ENTRIES}"

# --- samplers -----------------------------------------------------------
sample() { # $1 = lat file; runs until $TMP/stop-$2 exists
  : > "$1"
  ( while [ ! -f "$TMP/stop" ] && [ ! -f "$TMP/stop-$2" ]; do
      curl -s -m 70 -o /dev/null -w '%{time_total}\n' -H "$H" "$URL/api/hosts" >> "$1"; sleep 0.1
    done ) &
}
stop_sample() { touch "$TMP/stop-$1"; sleep 0.3; }
stats() { # $1 = lat file -> "n p50 p99 max"
  python3 -c "
import sys
v=sorted(float(x)*1000 for x in open(sys.argv[1]) if x.strip())
q=lambda p: v[min(len(v)-1,int(round(p*(len(v)-1))))] if v else 0
print('%d %.1f %.1f %.1f' % (len(v), q(.5), q(.99), v[-1] if v else 0))" "$1"
}
gate() { # $1 label, $2 lat file
  read -r n p50 p99 mx < <(stats "$2")
  if python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)" "$p99" "$MAX_P99_MS"; then
    log "$1: n=${n} p50 ${p50} ms, p99 ${p99} ms, max ${mx} ms (<= ${MAX_P99_MS}) PASS"
  else
    log "$1: n=${n} p50 ${p50} ms, p99 ${p99} ms, max ${mx} ms (> ${MAX_P99_MS}) FAIL"; RC=1
  fi
}
wait_purge_done() { # $1 = start mark; prints the log line
  local i line
  for i in $(seq 1 "$CAP_S"); do
    line=$(docker logs "$PANEL" --since "$1" 2>&1 | grep 'retention purge done' | tail -1)
    [ -n "$line" ] && { printf '%s' "$line"; return 0; }
    sleep 1
  done
  return 1
}

if [ "$IO_PRESSURE" = "1" ]; then
  log "io pressure: dd loop on ${IO_DIR} (256 MB, O_DIRECT + fsync) for the whole run"
  ( while [ ! -f "$TMP/stop" ]; do
      dd if=/dev/zero of="$IO_DIR/argos-io-pressure" bs=1M count=256 oflag=direct conv=fsync 2>/dev/null; sync
    done ) &
  sleep 5
fi

# --- 1. idle ------------------------------------------------------------
log "1/4 idle ${IDLE_S}s (pinned 24 h refresh every 24 s)"
sample "$TMP/idle" idle; sleep "$IDLE_S"; stop_sample idle
gate "idle" "$TMP/idle"

# --- 2. strip -----------------------------------------------------------
NEW_HOURS=$(( RAW_HOURS - STRIP_HOURS ))
[ "$NEW_HOURS" -ge 1 ] || { log "raw_hours ${RAW_HOURS} too small to strip ${STRIP_HOURS} h" >&2; exit 2; }
log "2/4 strip: raw_hours ${RAW_HOURS} -> ${NEW_HOURS}, POST /api/logs/purge"
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$H" -H 'Content-Type: application/json' \
  -d "{\"value\":\"${NEW_HOURS}\"}" "$URL/api/settings/logs.retention.raw_hours")
[ "$code" = "200" ] || { log "PUT raw_hours ${code}" >&2; exit 2; }
MARK=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sample "$TMP/strip" strip
curl -s -m "$CAP_S" -o /dev/null -w '[read-pool] purge %{http_code} in %{time_total}s\n' -X POST -H "$H" "$URL/api/logs/purge"
LINE=$(wait_purge_done "$MARK") || { stop_sample strip; log "strip purge did not finish in ${CAP_S}s" >&2; exit 2; }
stop_sample strip
curl -s -o /dev/null -X PUT -H "$H" -H 'Content-Type: application/json' -d "{\"value\":\"${RAW_HOURS}\"}" "$URL/api/settings/logs.retention.raw_hours"
STRIPPED=$(printf '%s' "$LINE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("raw_stripped",0))')
log "raw_stripped=${STRIPPED}"
[ "${STRIPPED:-0}" -gt 0 ] || { log "strip: nothing stripped FAIL"; RC=1; }
gate "strip" "$TMP/strip"

# --- 3. export x N ------------------------------------------------------
FROM=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)
log "3/4 export: ${EXPORT_RUNS} x GET /api/logs/export.csv?from=${FROM}&source=caddy_access"
sample "$TMP/export" export
for i in $(seq 1 "$EXPORT_RUNS"); do
  curl -s -m "$CAP_S" -o "$TMP/export.csv" -w "[read-pool] export ${i}: %{http_code} %{size_download} bytes in %{time_total}s\n" \
    -H "$H" "$URL/api/logs/export.csv?from=${FROM}&source=caddy_access"
done
stop_sample export
log "export rows per run: $(( $(wc -l < "$TMP/export.csv") - 1 ))"; rm -f "$TMP/export.csv"
gate "export x${EXPORT_RUNS} (aggregated)" "$TMP/export"

# --- 4. cap purge ---------------------------------------------------------
if [ "$CAP_PURGE_ROWS" -gt 0 ]; then
  CAP=$(( ROWS - CAP_PURGE_ROWS ))
  log "4/4 cap purge: max_entries ${MAX_ENTRIES} -> ${CAP} (about ${CAP_PURGE_ROWS} oldest rows + COUNT(*))"
  code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$H" -H 'Content-Type: application/json' \
    -d "{\"value\":\"${CAP}\"}" "$URL/api/settings/logs.max_entries")
  [ "$code" = "200" ] || { log "PUT max_entries ${code}" >&2; exit 2; }
  MARK=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  sample "$TMP/cap" cap
  curl -s -m "$CAP_S" -o /dev/null -w '[read-pool] purge %{http_code} in %{time_total}s\n' -X POST -H "$H" "$URL/api/logs/purge"
  LINE=$(wait_purge_done "$MARK") || { stop_sample cap; log "cap purge did not finish in ${CAP_S}s" >&2; exit 2; }
  stop_sample cap
  curl -s -o /dev/null -X PUT -H "$H" -H 'Content-Type: application/json' -d "{\"value\":\"${MAX_ENTRIES}\"}" "$URL/api/settings/logs.max_entries"
  log "removed=$(printf '%s' "$LINE" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("removed",0), "cap_counted=%s" % d.get("cap_counted"))')"
  gate "cap purge" "$TMP/cap"
else
  log "4/4 cap purge skipped (CAP_PURGE_ROWS=0)"
fi

[ $RC -eq 0 ] && log "PASS" || log "FAIL (kill-switch: ARGOS_READ_POOL=0 in .env + make deploy-prod)"
exit $RC
