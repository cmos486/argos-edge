#!/bin/bash
# scripts/smoke/range-7d-latency.sh
#
# v1.3.38.4 EFFECT smoke for the 7-day ranges.
#
# EFFECT verified against the live prod panel (curl -w, host-side):
#   1. GET /api/dashboard/traffic?range=7d answers 200 in <= MAX_SECONDS
#      on a cache miss. The cache key for 7d is not pinned, so the
#      first call after IDLE seconds is a real compute. Before
#      v1.3.38.4: 119.5 s on prod (five queries visiting every row in
#      the window, ~2.5 KB per row because of `raw`), during which the
#      single SQLite connection is held and every other request and
#      the log ingestor stall.
#   2. GET /api/logs/stats?from=<now-7d> answers 200 in <= MAX_SECONDS
#      on a cache miss (10 s stats cache). Before: 119.8 s.
#   3. GET /api/dashboard/traffic?range=7d&host_id=<busiest host> answers
#      in <= MAX_SECONDS (v1.3.38.4 bounds that case to the newest 24 h).
#
# WARNING: on a panel without the fix this smoke blocks the prod panel
# for ~4 minutes total (two 2-minute computes). Run it as the "before"
# measurement once, deliberately, outside traffic hours.
#
# Usage:
#   ARGOS_SESSION_TOKEN=<cookie> [MAX_SECONDS=5] [IDLE=40] scripts/smoke/range-7d-latency.sh
#
# Exit codes: 0 PASS, 1 FAIL, 2 precondition
set -u
URL="${ARGOS_URL:-http://127.0.0.1:9180}"
TOKEN="${ARGOS_SESSION_TOKEN:-}"
MAX="${MAX_SECONDS:-5}"
IDLE="${IDLE:-40}"
[ -n "$TOKEN" ] || { echo "[range-7d] ARGOS_SESSION_TOKEN required" >&2; exit 2; }
FROM7D=$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)
le() { python3 -c "import sys; sys.exit(0 if float('$1') <= float('$2') else 1)"; }
probe() { curl -s -H "Cookie: argos_session=${TOKEN}" -o /dev/null -w '%{http_code} %{time_total}' "${URL}${1}"; }
code=$(probe /api/auth/me | cut -d' ' -f1); [ "$code" = "200" ] || { echo "[range-7d] /api/auth/me ${code}" >&2; exit 2; }

# Busiest host (by 24 h volume) for the host-filtered 7d case, which no
# index can answer without visiting that host's rows: v1.3.38.4 bounds
# it to the newest 24 h (series_covers_range=false) so it stays under
# MAX_SECONDS like the others.
BODY=$(mktemp); trap 'rm -f "$BODY"' EXIT
curl -s -H "Cookie: argos_session=${TOKEN}" -o "$BODY" "${URL}/api/dashboard/traffic?range=24h"
TOPDOM=$(python3 -c "import json; d=json.load(open('$BODY')); print(d['top_hosts'][0]['host_domain'] if d.get('top_hosts') else '')")
curl -s -H "Cookie: argos_session=${TOKEN}" -o "$BODY" "${URL}/api/hosts"
TOPID=$(python3 -c "import json,sys; hs=json.load(open('$BODY')); m=[h['id'] for h in hs if h['domain']=='$TOPDOM']; print(m[0] if m else '')")
HOSTEP=""; [ -n "$TOPID" ] && HOSTEP="/api/dashboard/traffic?range=7d&host_id=${TOPID}"

rc=0
for ep in "/api/dashboard/traffic?range=7d" "/api/logs/stats?from=${FROM7D}" $HOSTEP; do
  echo "[range-7d] idle ${IDLE}s so any cached value for ${ep%%\?*} expires..."
  sleep "$IDLE"
  out=$(probe "$ep"); code=${out%% *}; secs=${out##* }
  if [ "$code" != "200" ]; then echo "[range-7d] ${ep}: http ${code}" >&2; exit 2; fi
  if le "$secs" "$MAX"; then echo "[range-7d] ${ep}: cold ${secs}s (<= ${MAX}s) PASS"; else echo "[range-7d] ${ep}: cold ${secs}s (> ${MAX}s) FAIL"; rc=1; fi
done
[ -z "$HOSTEP" ] && echo "[range-7d] no host with 24 h traffic found; host-filtered case skipped"
[ $rc -eq 0 ] && echo "[range-7d] PASS" || echo "[range-7d] FAIL"
exit $rc
