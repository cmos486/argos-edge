#!/bin/bash
# scripts/smoke/certs-latency.sh
#
# v1.3.38.3 EFFECT smoke for the Certificates list.
#
# EFFECT verified against the live prod panel (curl -w, host-side):
#   1. GET /api/certs answers 200 in <= MAX_LIST_SECONDS (default 0.3).
#      Before v1.3.38.3 it took 1.06-1.6 s on the operator's 19 hosts:
#      the shared TLS probe pass (v1.3.38.2) had removed the dials and
#      the rest was enrichWithLastEvent, one LIKE over every caddy_error
#      row per host, sequential. The list no longer computes it.
#   2. The list rows carry no last_renewal_event (moved on demand).
#   3. GET /api/certs/{id}/last-event for the first listed host answers
#      200 in <= MAX_EVENT_SECONDS (default 0.5) with a JSON object that
#      has "event" (object or null) and "matched_by".
#
# Usage:
#   ARGOS_SESSION_TOKEN=<argos_session cookie value> scripts/smoke/certs-latency.sh
#
# Env:
#   ARGOS_SESSION_TOKEN  session cookie value (required)
#   ARGOS_URL            panel base URL (default http://127.0.0.1:9180)
#   MAX_LIST_SECONDS     (default 0.3)
#   MAX_EVENT_SECONDS    (default 0.5)
#
# Exit codes: 0 PASS, 1 FAIL, 2 precondition (token, non-200, no hosts)
set -u
URL="${ARGOS_URL:-http://127.0.0.1:9180}"
TOKEN="${ARGOS_SESSION_TOKEN:-}"
MAXL="${MAX_LIST_SECONDS:-0.3}"
MAXE="${MAX_EVENT_SECONDS:-0.5}"
[ -n "$TOKEN" ] || { echo "[certs-latency] ARGOS_SESSION_TOKEN required" >&2; exit 2; }
BODY=$(mktemp); trap 'rm -f "$BODY"' EXIT
le() { python3 -c "import sys; sys.exit(0 if float('$1') <= float('$2') else 1)"; }

out=$(curl -s -H "Cookie: argos_session=${TOKEN}" -o "$BODY" -w '%{http_code} %{time_total}' "${URL}/api/certs")
code=${out%% *}; secs=${out##* }
[ "$code" = "200" ] || { echo "[certs-latency] /api/certs http ${code}" >&2; exit 2; }
rc=0
if le "$secs" "$MAXL"; then echo "[certs-latency] /api/certs ${secs}s (<= ${MAXL}s) PASS"; else echo "[certs-latency] /api/certs ${secs}s (> ${MAXL}s) FAIL"; rc=1; fi

read -r n_rows n_with_event first_id <<<"$(python3 -c "
import json,sys
rows=json.load(open('$BODY'))
print(len(rows), sum(1 for r in rows if r.get('last_renewal_event')), rows[0]['host_id'] if rows else '')")"
[ -n "$first_id" ] || { echo "[certs-latency] no auto hosts listed; nothing to check" >&2; exit 2; }
if [ "$n_with_event" = "0" ]; then echo "[certs-latency] ${n_rows} rows, none carries last_renewal_event inline PASS"; else echo "[certs-latency] ${n_with_event}/${n_rows} rows still carry last_renewal_event inline FAIL"; rc=1; fi

out=$(curl -s -H "Cookie: argos_session=${TOKEN}" -o "$BODY" -w '%{http_code} %{time_total}' "${URL}/api/certs/${first_id}/last-event")
code=${out%% *}; secs=${out##* }
if [ "$code" != "200" ]; then echo "[certs-latency] last-event http ${code} FAIL"; rc=1
else
  shape=$(python3 -c "
import json; d=json.load(open('$BODY')); print('ok' if ('event' in d and 'matched_by' in d) else 'bad', d.get('matched_by') or '-', 'null' if d.get('event') is None else 'event')")
  if le "$secs" "$MAXE" && [ "${shape%% *}" = "ok" ]; then echo "[certs-latency] last-event host ${first_id}: ${secs}s, ${shape#ok } PASS"; else echo "[certs-latency] last-event host ${first_id}: ${secs}s shape=${shape} FAIL"; rc=1; fi
fi
[ $rc -eq 0 ] && echo "[certs-latency] PASS" || echo "[certs-latency] FAIL"
exit $rc
