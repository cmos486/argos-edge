#!/bin/bash
# scripts/smoke/country-reconciler.sh
#
# v1.3.33 smoke gate: verifies the country reconciler health
# check flips state='drifted' when LAPI diverges from panel
# state, and recovers to state='active' when re-synced.
#
# Phases:
#   1. Expand a country via panel -> verify panel shows
#      state='active'
#   2. Manually delete LAPI decisions via cscli (simulate the
#      v1.3.31-era flush cascade)
#   3. Trigger reconciler tick (CheckOnce via internal API or
#      wait DefaultReconcilerInterval + buffer)
#   4. Verify panel surfaces state='drifted'
#   5. Re-add country -> verify reconciler flips back to active
#   6. Cleanup
#
# The reconciler runs every 5 min by default. To avoid a 5+ min
# wait the smoke uses TICK_WAIT (default 320s = 5min + buffer).
# Operator can lower this by configuring a shorter interval at
# startup (env var or build flag), but we don't expose that
# control via API in v1.3.33; tweaking is for follow-up.
#
# Usage:
#   PANEL_BASE_URL=http://localhost:9180 \
#   ARGOS_SESSION_TOKEN=<cookie value> \
#   CROWDSEC_CONTAINER=argos-prod-crowdsec \
#   TEST_COUNTRY=NG \
#     ./scripts/smoke/country-reconciler.sh
#
# Tunables:
#   TEST_COUNTRY  ISO code to expand. Defaults XX (refuses to
#                 run; isolation gate). Pick a SMALL country
#                 (NG ~471 ranges) for fast smoke turnaround.
#   TICK_WAIT     seconds to wait for the reconciler tick after
#                 inducing drift. Default 320s (5min + 20s).
#                 Lower if your stack runs the reconciler
#                 faster.
#
# Exit codes:
#   0 = drift detected + recovery observed
#   1 = an assertion diverged
#   2 = setup error

set -euo pipefail

PANEL_BASE_URL="${PANEL_BASE_URL:-http://localhost:9180}"
ARGOS_SESSION_TOKEN="${ARGOS_SESSION_TOKEN:-}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-argos-prod-crowdsec}"
TEST_COUNTRY="${TEST_COUNTRY:-XX}"
TICK_WAIT="${TICK_WAIT:-320}"
POLL_TIMEOUT="${POLL_TIMEOUT:-120}"

log()  { printf '[smoke/country-reconciler] %s\n' "$*"; }
fail() { printf '[smoke/country-reconciler] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() {
    printf '[smoke/country-reconciler] SETUP: %s\n' "$*" >&2
    exit 2
}

[ -n "${ARGOS_SESSION_TOKEN}" ] || setup_fail "ARGOS_SESSION_TOKEN required"
docker ps --format '{{.Names}}' | grep -qx "${CROWDSEC_CONTAINER}" \
    || setup_fail "container ${CROWDSEC_CONTAINER} not running"
command -v jq >/dev/null 2>&1 || setup_fail "jq required"
[ "${TEST_COUNTRY}" != "XX" ] || setup_fail "TEST_COUNTRY is the placeholder; export a real code (e.g. NG for ~471 ranges)"

cleanup() {
    log "cleanup: revoke ${TEST_COUNTRY}"
    curl -fsS -X DELETE \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        "${PANEL_BASE_URL}/api/security/countries/${TEST_COUNTRY}" \
        >/dev/null 2>&1 || true
}
trap cleanup EXIT

get_state() {
    curl -fsS -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        "${PANEL_BASE_URL}/api/security/countries" \
    | jq -r --arg cc "${TEST_COUNTRY}" \
        '.[] | select(.country_code == $cc) | .state'
}

submit_and_wait() {
    local cc="$1"
    local resp
    resp=$(curl -fsS -X POST \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{"duration":"4h","reason":"reconciler smoke"}' \
        "${PANEL_BASE_URL}/api/security/countries/${cc}/expand")
    local job_id
    job_id=$(echo "${resp}" | jq -r .id)
    [ -n "${job_id}" ] && [ "${job_id}" != "null" ] \
        || fail "submit ${cc}: no job_id in ${resp}"
    local deadline=$((SECONDS + POLL_TIMEOUT))
    while [ $SECONDS -lt $deadline ]; do
        sleep 1
        local state
        state=$(curl -fsS \
            -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
            "${PANEL_BASE_URL}/api/security/jobs/${job_id}" \
            | jq -r .state)
        case "${state}" in
            completed|failed)
                [ "${state}" = "completed" ] \
                    || fail "${cc} job ${job_id}: state=${state}"
                return 0
                ;;
        esac
    done
    fail "${cc} job ${job_id} did not terminate within ${POLL_TIMEOUT}s"
}

# === phase 1: expand + verify state=active ===================
log "[1/5] expand ${TEST_COUNTRY} via panel"
submit_and_wait "${TEST_COUNTRY}"
sleep 3  # reconciler boot-time tick should have run; row default is active
STATE=$(get_state)
[ "${STATE}" = "active" ] \
    || fail "expected state=active right after expand, got ${STATE}"
log "  state=${STATE}"

# === phase 2: induce drift via cscli ==========================
log "[2/5] simulate drift: cscli decisions delete --origin argos-country-${TEST_COUNTRY}"
docker exec "${CROWDSEC_CONTAINER}" cscli decisions delete \
    --origin "argos-country-${TEST_COUNTRY}" >/dev/null 2>&1 || true
sleep 2

# === phase 3: wait for reconciler tick =======================
log "[3/5] wait ${TICK_WAIT}s for reconciler tick (DefaultReconcilerInterval=300s)"
sleep "${TICK_WAIT}"

# === phase 4: assert state=drifted ===========================
log "[4/5] assert state=drifted"
STATE=$(get_state)
if [ "${STATE}" != "drifted" ]; then
    fail "expected state=drifted after manual cscli delete + tick, got ${STATE}"
fi
log "  PASS: reconciler flipped state to drifted"

# === phase 5: re-emit -> recover to active ===================
log "[5/5] re-emit ${TEST_COUNTRY} -> reconciler should flip back to active"
submit_and_wait "${TEST_COUNTRY}"
sleep "${TICK_WAIT}"
STATE=$(get_state)
[ "${STATE}" = "active" ] \
    || fail "expected state=active after re-emit, got ${STATE}"

log "PASS: reconciler drift detection + recovery verified"
