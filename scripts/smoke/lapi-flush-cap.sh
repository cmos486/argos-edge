#!/bin/bash
# scripts/smoke/lapi-flush-cap.sh
#
# v1.3.33 smoke gate: verifies the AddRangeDecisions shape
# restructure prevents the v1.3.31-era flush cascade.
#
# Pre-v1.3.33: argos emitted 1 LAPI alert per CIDR. A 5009-CIDR
# country expansion produced 5009 alerts that immediately blew
# CrowdSec's flush.max_items: 5000 default and silently flushed
# older argos-country-* alerts (decisions cascade-deleted).
#
# Post-v1.3.33: 1 alert per chunk-call carrying up to 500
# decisions inside (CAPI/community-blocklist pattern, with
# v1.3.22's per-chunk failure isolation preserved). A country
# expansion adds ceil(cidr_count / 500) alerts -- never close
# to the 5000 cap even for 25-country pile-ups.
#
# Concrete numbers:
#   country     ranges   chunks (= alerts)
#   ----------- -------- ------------------
#   NG            471    1
#   IR           1454    3
#   BR           5009    11
#   sum of 25 countries averaging 2000 ranges each: ~100 alerts
#
# So we assert delta == expected_chunks per country, not 1.
#
# Smoke gates:
#   1. Snapshot pre-test alert count (baseline)
#   2. Add a moderate-size country (e.g. BR via panel API)
#   3. Snapshot post-add alert count
#   4. Assert delta == 1 (not 5009)
#   5. Repeat for a SECOND country (e.g. NG; smaller)
#   6. Assert post-add delta == 1 again (no flush cascade)
#   7. Assert decision count grew by both countries' CIDR sums
#   8. Cleanup both countries
#
# Smoke verifies EFFECT (per the working agreement v1.3.20+):
# the alert count behaviour empirically validates the shape
# fix, the decision count validates that LAPI accepted the
# new shape, and the multi-country scenario validates the
# absence of cascade flush.
#
# Usage:
#   PANEL_BASE_URL=http://localhost:9180 \
#   ARGOS_SESSION_TOKEN=<cookie value> \
#   CROWDSEC_CONTAINER=argos-prod-crowdsec \
#   TEST_COUNTRY_A=BR \
#   TEST_COUNTRY_B=NG \
#     ./scripts/smoke/lapi-flush-cap.sh
#
# TEST_COUNTRY_A defaults XX (refuses to run; isolation gate).
# Operator picks two real codes; the smoke wipes them on cleanup.
#
# Exit codes:
#   0 = full round-trip works; alert count grew by 2 (one per
#       country) and decision count grew by full sum
#   1 = an assertion diverged
#   2 = setup error

set -euo pipefail

PANEL_BASE_URL="${PANEL_BASE_URL:-http://localhost:9180}"
ARGOS_SESSION_TOKEN="${ARGOS_SESSION_TOKEN:-}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-argos-prod-crowdsec}"
TEST_COUNTRY_A="${TEST_COUNTRY_A:-XX}"
TEST_COUNTRY_B="${TEST_COUNTRY_B:-YY}"
POLL_TIMEOUT="${POLL_TIMEOUT:-120}"

log()  { printf '[smoke/lapi-flush-cap] %s\n' "$*"; }
fail() { printf '[smoke/lapi-flush-cap] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() {
    printf '[smoke/lapi-flush-cap] SETUP: %s\n' "$*" >&2
    exit 2
}

[ -n "${ARGOS_SESSION_TOKEN}" ] || setup_fail "ARGOS_SESSION_TOKEN required"
docker ps --format '{{.Names}}' | grep -qx "${CROWDSEC_CONTAINER}" \
    || setup_fail "container ${CROWDSEC_CONTAINER} not running"
command -v jq >/dev/null 2>&1 || setup_fail "jq required"
if [ "${TEST_COUNTRY_A}" = "XX" ] || [ "${TEST_COUNTRY_B}" = "YY" ]; then
    setup_fail "TEST_COUNTRY_A/B are placeholders; export real codes before running"
fi

cleanup() {
    log "cleanup: revoke ${TEST_COUNTRY_A} + ${TEST_COUNTRY_B}"
    for cc in "${TEST_COUNTRY_A}" "${TEST_COUNTRY_B}"; do
        curl -fsS -X DELETE \
            -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
            "${PANEL_BASE_URL}/api/security/countries/${cc}" \
            >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

count_alerts() {
    docker exec "${CROWDSEC_CONTAINER}" sh -c \
        "sqlite3 /var/lib/crowdsec/data/crowdsec.db 'SELECT COUNT(*) FROM alerts'" \
        2>/dev/null
}

count_decisions_origin() {
    local origin="$1"
    docker exec "${CROWDSEC_CONTAINER}" sh -c \
        "sqlite3 /var/lib/crowdsec/data/crowdsec.db \"SELECT COUNT(*) FROM decisions WHERE origin='${origin}' AND until > datetime('now')\"" \
        2>/dev/null
}

submit_and_wait() {
    local cc="$1"
    local resp
    resp=$(curl -fsS -X POST \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{"duration":"4h","reason":"v1.3.33 lapi-flush-cap smoke"}' \
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
                echo "${state}"
                return 0
                ;;
        esac
    done
    fail "${cc} job ${job_id} did not terminate within ${POLL_TIMEOUT}s"
}

# === phase 1: pre-test snapshot ===============================
log "[1/8] pre-test alert count snapshot"
ALERTS_BEFORE=$(count_alerts)
log "  alerts table size: ${ALERTS_BEFORE}"

# === phase 2-4: country A, expect +1 alert ===================
log "[2/8] expand ${TEST_COUNTRY_A} via panel"
STATE_A=$(submit_and_wait "${TEST_COUNTRY_A}")
[ "${STATE_A}" = "completed" ] || fail "${TEST_COUNTRY_A} did not complete: ${STATE_A}"

log "[3/8] post-${TEST_COUNTRY_A} alert count"
ALERTS_AFTER_A=$(count_alerts)
log "  alerts table size: ${ALERTS_AFTER_A}"

DEC_A=$(count_decisions_origin "argos-country-${TEST_COUNTRY_A}")
log "  decisions for argos-country-${TEST_COUNTRY_A}: ${DEC_A}"
[ "${DEC_A}" -gt 0 ] \
    || fail "${TEST_COUNTRY_A} has 0 decisions -- alert was accepted but decisions weren't persisted"

DELTA_A=$((ALERTS_AFTER_A - ALERTS_BEFORE))
EXPECTED_A=$(( (DEC_A + 499) / 500 ))
log "[4/8] assert ${TEST_COUNTRY_A} added ${EXPECTED_A} alerts (= ceil(${DEC_A} / 500); v1.3.22 chunking + v1.3.33 CAPI shape)"
if [ "${DELTA_A}" -ne "${EXPECTED_A}" ]; then
    # Cap-of-5000 pre-v1.3.33 shape would have produced ~${DEC_A} alerts
    # for this country alone -- a clear regression. Refuse to ship
    # silently broken state.
    fail "expected delta=${EXPECTED_A} chunk-alerts; got ${DELTA_A}. If delta=${DEC_A}, the v1.3.33 shape regressed back to per-CIDR; if 0, the LAPI rejected the new shape"
fi
log "  PASS: chunk-shape confirmed (1 alert per 500-CIDR chunk)"

# === phase 5-7: country B, no flush cascade ==================
log "[5/8] expand ${TEST_COUNTRY_B} via panel"
STATE_B=$(submit_and_wait "${TEST_COUNTRY_B}")
[ "${STATE_B}" = "completed" ] || fail "${TEST_COUNTRY_B} did not complete: ${STATE_B}"

log "[6/8] post-${TEST_COUNTRY_B} alert count"
ALERTS_AFTER_B=$(count_alerts)
log "  alerts table size: ${ALERTS_AFTER_B}"
DELTA_B=$((ALERTS_AFTER_B - ALERTS_AFTER_A))
DEC_B=$(count_decisions_origin "argos-country-${TEST_COUNTRY_B}")
EXPECTED_B=$(( (DEC_B + 499) / 500 ))
log "  ${TEST_COUNTRY_B} decisions: ${DEC_B} -> expected ${EXPECTED_B} chunk-alerts"
[ "${DELTA_B}" -eq "${EXPECTED_B}" ] \
    || fail "${TEST_COUNTRY_B} delta=${DELTA_B} (expected ${EXPECTED_B} chunks); shape regressed for the second call"

log "[7/8] both countries' decisions still active (no flush cascade)"
DEC_A_AFTER=$(count_decisions_origin "argos-country-${TEST_COUNTRY_A}")
log "  ${TEST_COUNTRY_A}: ${DEC_A_AFTER} decisions (was ${DEC_A})"
log "  ${TEST_COUNTRY_B}: ${DEC_B} decisions"
[ "${DEC_A_AFTER}" -ge "${DEC_A}" ] \
    || fail "${TEST_COUNTRY_A} decisions decreased after adding ${TEST_COUNTRY_B} (was ${DEC_A}, now ${DEC_A_AFTER}) -- flush cascade is back"

# === phase 8: cleanup (handled by trap) ======================
log "[8/8] PASS: 2 countries added, ${EXPECTED_A}+${EXPECTED_B} chunk-alerts total, no decision loss"
log "  pre-test alerts:   ${ALERTS_BEFORE}"
log "  post-A alerts:     ${ALERTS_AFTER_A} (+${EXPECTED_A} chunks)"
log "  post-B alerts:     ${ALERTS_AFTER_B} (+${EXPECTED_B} chunks)"
log "  ${TEST_COUNTRY_A} decisions: ${DEC_A_AFTER}"
log "  ${TEST_COUNTRY_B} decisions: ${DEC_B}"
