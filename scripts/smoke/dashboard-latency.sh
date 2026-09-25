#!/bin/bash
# scripts/smoke/dashboard-latency.sh
#
# v1.3.38.1 EFFECT smoke for cold dashboard latency.
#
# Feature under test: the aggregate endpoints behind the Dashboard
# health card and the Security overview page. Both sit behind a 30 s
# in-memory cache that recomputes synchronously on the first request
# after expiry, so the number an operator feels is the COLD number.
#   - GET /api/dashboard/health   (v1.3.38.1: RecentErrors bounded to
#                                   24 h as two indexed sub-selects)
#   - GET /api/security/overview  (v1.3.38.1: one grouped query for
#                                   all hosts instead of 3 x N)
#
# EFFECT verified: after IDLE seconds without touching either endpoint
# (longer than the 30 s cache TTL), one request to each returns 200
# in <= MAX_SECONDS, measured with curl -w %{time_total} from the host
# against the live prod panel. Prod density (500k log_entries rows),
# not a mock. Baseline on 1.3.38.0: health 21-31 s, overview 30-36 s.
#
# Usage:
#   ARGOS_SESSION_TOKEN=<argos_session cookie value> \
#   [ARGOS_URL=http://127.0.0.1:9180] [IDLE=40] [MAX_SECONDS=2] \
#     scripts/smoke/dashboard-latency.sh
#
# Env:
#   ARGOS_SESSION_TOKEN  session cookie value (required)
#   ARGOS_URL            panel base URL (default http://127.0.0.1:9180)
#   IDLE                 seconds to wait before each cold call (default 40)
#   MAX_SECONDS          PASS threshold per endpoint, inclusive (default 2)
#
# Exit codes:
#   0  PASS: both endpoints 200 and <= MAX_SECONDS cold
#   1  FAIL: an endpoint exceeded MAX_SECONDS
#   2  precondition failed (no token, non-200, curl error)
set -u

URL="${ARGOS_URL:-http://127.0.0.1:9180}"
TOKEN="${ARGOS_SESSION_TOKEN:-}"
IDLE="${IDLE:-40}"
MAX="${MAX_SECONDS:-2}"

[ -n "$TOKEN" ] || { echo "[dashboard-latency] ARGOS_SESSION_TOKEN required" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "[dashboard-latency] curl missing" >&2; exit 2; }

probe() {
  # prints "<http_code> <seconds>"
  curl -s -o /dev/null -w '%{http_code} %{time_total}' \
    -H "Cookie: argos_session=${TOKEN}" "${URL}${1}"
}

# Sanity: the session must work before we wait.
code=$(probe /api/auth/me | cut -d' ' -f1)
[ "$code" = "200" ] || { echo "[dashboard-latency] /api/auth/me returned ${code}; bad token or URL" >&2; exit 2; }

rc=0
for ep in /api/dashboard/health /api/security/overview; do
  echo "[dashboard-latency] idle ${IDLE}s so the 30 s cache for ${ep} expires..."
  sleep "$IDLE"
  out=$(probe "$ep") || { echo "[dashboard-latency] curl failed on ${ep}" >&2; exit 2; }
  code=${out%% *}; secs=${out##* }
  if [ "$code" != "200" ]; then
    echo "[dashboard-latency] ${ep}: http ${code}" >&2; exit 2
  fi
  # bash has no float compare; use awk.
  if awk -v s="$secs" -v m="$MAX" 'BEGIN{exit !(s <= m)}'; then
    echo "[dashboard-latency] ${ep}: cold ${secs}s  (<= ${MAX}s) PASS"
  else
    echo "[dashboard-latency] ${ep}: cold ${secs}s  (>  ${MAX}s) FAIL"
    rc=1
  fi
done

if [ $rc -eq 0 ]; then
  echo "[dashboard-latency] PASS"
else
  echo "[dashboard-latency] FAIL"
fi
exit $rc
