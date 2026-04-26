#!/bin/bash
# scripts/smoke/country-expansion-async.sh
#
# v1.3.31 smoke gate: async country expansion end-to-end.
# Submit -> 202 + job_id -> poll until completed -> assert
# decisions count -> failure path (LAPI down) -> assert failed.
#
# Smoke verifies EFFECT (per the working agreement v1.3.20+):
# the panel really queues the work, the worker really expands
# the country into LAPI, the polling endpoint really tracks
# progress, and the failure path really records error_message.
#
# Phase 5/6/7 simulate LAPI down by stopping the crowdsec
# container. ~15s of LAPI downtime; on this homelab the public
# stack is fronted by Zoraxy NAT so the operator's actual
# argos-prod blip is observable but not catastrophic. If you
# want to skip the failure path, set SKIP_FAILURE_PATH=1.
#
# Usage:
#   PANEL_BASE_URL=http://localhost:9180 \
#   ARGOS_SESSION_TOKEN=<cookie value> \
#   CROWDSEC_CONTAINER=argos-prod-crowdsec \
#   COMPOSE_DIR=/home/claude/argos-prod \
#     ./scripts/smoke/country-expansion-async.sh
#
# Tunables:
#   TEST_COUNTRY        country to expand (default BR -- ~5009 ranges)
#   FAIL_TEST_COUNTRY   country to use for the failure path (default TR)
#   POLL_TIMEOUT        max seconds to wait for completion (default 120)
#   SKIP_FAILURE_PATH   1 to skip phases 5/6/7 (default 0)
#
# Exit codes:
#   0 = all phases pass
#   1 = an assertion diverged
#   2 = setup error

set -euo pipefail

PANEL_BASE_URL="${PANEL_BASE_URL:-http://localhost:9180}"
ARGOS_SESSION_TOKEN="${ARGOS_SESSION_TOKEN:-}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-argos-prod-crowdsec}"
COMPOSE_DIR="${COMPOSE_DIR:-$HOME/argos-prod}"
# v1.3.33 isolation: defaults are RFC 3166 reserved codes (XX/YY)
# that the GeoIP DB rejects with ErrCountryNotFound. The smoke
# refuses to run with placeholders so a bare invocation cannot
# accidentally DELETE operator-created BR/TR expansions on
# cleanup. Operator must explicitly pass real codes:
#   TEST_COUNTRY=BR FAIL_TEST_COUNTRY=TR ./...
TEST_COUNTRY="${TEST_COUNTRY:-XX}"
FAIL_TEST_COUNTRY="${FAIL_TEST_COUNTRY:-YY}"
POLL_TIMEOUT="${POLL_TIMEOUT:-120}"
SKIP_FAILURE_PATH="${SKIP_FAILURE_PATH:-0}"

log()  { printf '[smoke/country-async] %s\n' "$*"; }
fail() { printf '[smoke/country-async] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() {
    printf '[smoke/country-async] SETUP: %s\n' "$*" >&2
    exit 2
}

[ -n "${ARGOS_SESSION_TOKEN}" ] || setup_fail "ARGOS_SESSION_TOKEN required"
docker ps --format '{{.Names}}' | grep -qx "${CROWDSEC_CONTAINER}" \
    || setup_fail "container ${CROWDSEC_CONTAINER} is not running"
[ -d "${COMPOSE_DIR}" ] || setup_fail "compose dir ${COMPOSE_DIR} not found"
command -v jq >/dev/null 2>&1 || setup_fail "jq required"

# v1.3.33 isolation gate: refuse to run with placeholder codes.
# Otherwise cleanup() would issue blind DELETEs against operator-
# created country expansions. v1.3.31-era smoke contamination was
# the symptom that drove this gate.
if [ "${TEST_COUNTRY}" = "XX" ] || [ "${FAIL_TEST_COUNTRY}" = "YY" ]; then
    setup_fail "TEST_COUNTRY/FAIL_TEST_COUNTRY are placeholders. Export real codes (e.g. TEST_COUNTRY=BR FAIL_TEST_COUNTRY=TR) before running."
fi

cleanup() {
    log "cleanup: ensure crowdsec is up + revoke test countries"
    if ! docker ps --format '{{.Names}}' | grep -qx "${CROWDSEC_CONTAINER}"; then
        ( cd "${COMPOSE_DIR}" && docker compose start crowdsec ) >/dev/null 2>&1 || true
        sleep 5
    fi
    curl -fsS -X DELETE \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        "${PANEL_BASE_URL}/api/security/countries/${TEST_COUNTRY}" \
        >/dev/null 2>&1 || true
    curl -fsS -X DELETE \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        "${PANEL_BASE_URL}/api/security/countries/${FAIL_TEST_COUNTRY}" \
        >/dev/null 2>&1 || true
}
trap cleanup EXIT

submit() {
    local cc="$1"
    curl -fsS -X POST \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{"duration":"4h","reason":"smoke test"}' \
        "${PANEL_BASE_URL}/api/security/countries/${cc}/expand"
}

get_job() {
    local id="$1"
    curl -fsS \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        "${PANEL_BASE_URL}/api/security/jobs/${id}"
}

poll_until_terminal() {
    local id="$1"
    local timeout="$2"
    local deadline=$((SECONDS + timeout))
    while [ $SECONDS -lt $deadline ]; do
        local j
        j=$(get_job "${id}")
        local state
        state=$(echo "${j}" | jq -r .state)
        case "${state}" in
            completed|failed)
                echo "${j}"
                return 0
                ;;
        esac
        sleep 1
    done
    echo "${j}"
    return 1
}

# === phase 1 + 2: submit + 202 + poll =========================
log "[1/8] POST /api/security/countries/${TEST_COUNTRY}/expand -> 202 + job_id"
RESP=$(submit "${TEST_COUNTRY}")
JOB_ID=$(echo "${RESP}" | jq -r .id)
[ -n "${JOB_ID}" ] && [ "${JOB_ID}" != "null" ] \
    || fail "submit did not return a job_id: ${RESP}"
INITIAL_STATE=$(echo "${RESP}" | jq -r .state)
log "  job_id=${JOB_ID} initial state=${INITIAL_STATE}"
[ "${INITIAL_STATE}" = "pending" ] || [ "${INITIAL_STATE}" = "running" ] \
    || fail "expected pending/running on submit, got ${INITIAL_STATE}"

log "[2/8] poll until terminal (timeout ${POLL_TIMEOUT}s)"
FINAL=$(poll_until_terminal "${JOB_ID}" "${POLL_TIMEOUT}") \
    || fail "job did not reach terminal state within ${POLL_TIMEOUT}s: ${FINAL}"

# === phase 3: assert completed + counts =======================
log "[3/8] assert state=completed + chunks_done=chunks_total"
STATE=$(echo "${FINAL}" | jq -r .state)
CHUNKS_DONE=$(echo "${FINAL}" | jq -r .chunks_done)
CHUNKS_TOTAL=$(echo "${FINAL}" | jq -r .chunks_total)
CIDR_COMMITTED=$(echo "${FINAL}" | jq -r .cidr_committed)
[ "${STATE}" = "completed" ] \
    || fail "expected completed, got ${STATE}: ${FINAL}"
[ "${CHUNKS_DONE}" = "${CHUNKS_TOTAL}" ] \
    || fail "chunks_done=${CHUNKS_DONE} != chunks_total=${CHUNKS_TOTAL}"
log "  ${CHUNKS_DONE}/${CHUNKS_TOTAL} chunks; ${CIDR_COMMITTED} ranges committed"

# === phase 4: cscli decisions count matches ===================
log "[4/8] cscli decisions list --origin argos-country-${TEST_COUNTRY} > 4000"
# cscli decisions list paginates at 100 by default. Pass --limit 0
# to remove the cap so we count the actual stored set.
DECISION_COUNT=$(docker exec "${CROWDSEC_CONTAINER}" \
    cscli decisions list --origin "argos-country-${TEST_COUNTRY}" --limit 0 -o raw 2>/dev/null \
    | tail -n +2 | wc -l)
log "  ${DECISION_COUNT} decisions tagged argos-country-${TEST_COUNTRY}"
[ "${DECISION_COUNT}" -gt 4000 ] \
    || fail "expected > 4000 decisions for ${TEST_COUNTRY}, got ${DECISION_COUNT}"

if [ "${SKIP_FAILURE_PATH}" = "1" ]; then
    log "SKIP_FAILURE_PATH=1; skipping phases 5/6/7"
    log "PASS (happy-path only): submit + poll + complete + decisions"
    exit 0
fi

# === phase 5/6/7: failure path with LAPI down =================
log "[5/8] stop crowdsec to simulate LAPI down"
( cd "${COMPOSE_DIR}" && docker compose stop crowdsec ) >/dev/null 2>&1
sleep 3

log "[6/8] POST /api/security/countries/${FAIL_TEST_COUNTRY}/expand"
FAIL_RESP=$(submit "${FAIL_TEST_COUNTRY}")
FAIL_JOB_ID=$(echo "${FAIL_RESP}" | jq -r .id)
[ -n "${FAIL_JOB_ID}" ] && [ "${FAIL_JOB_ID}" != "null" ] \
    || fail "failure-path submit did not return a job_id: ${FAIL_RESP}"
log "  job_id=${FAIL_JOB_ID}"

log "[7/8] poll until terminal -> assert failed + error_message populated"
FAIL_FINAL=$(poll_until_terminal "${FAIL_JOB_ID}" "${POLL_TIMEOUT}") \
    || fail "failure-path job did not terminate: ${FAIL_FINAL}"
FAIL_STATE=$(echo "${FAIL_FINAL}" | jq -r .state)
FAIL_MSG=$(echo "${FAIL_FINAL}" | jq -r .error_message)
[ "${FAIL_STATE}" = "failed" ] \
    || fail "expected failed, got ${FAIL_STATE}: ${FAIL_FINAL}"
[ -n "${FAIL_MSG}" ] && [ "${FAIL_MSG}" != "null" ] \
    || fail "error_message empty on failed job: ${FAIL_FINAL}"
log "  state=${FAIL_STATE} error_message='${FAIL_MSG}'"

# === phase 8: restart crowdsec + cleanup ======================
log "[8/8] start crowdsec back, wait for healthy"
( cd "${COMPOSE_DIR}" && docker compose start crowdsec ) >/dev/null 2>&1
# crowdsec's first health check fires ~10-15s after start; the
# healthcheck cadence is 15s. Wait up to 30s before failing.
HEALTHY=0
for i in 1 2 3 4 5 6; do
    sleep 5
    if docker ps --filter "name=${CROWDSEC_CONTAINER}" --format '{{.Status}}' | grep -q healthy; then
        HEALTHY=1
        break
    fi
done
[ "${HEALTHY}" = 1 ] || fail "crowdsec did not return to healthy within 30s"

log "PASS: async country expansion end-to-end (happy + failure paths)"
