#!/bin/bash
# scripts/smoke/drift-detection.sh
#
# End-to-end verification of the v1.3.27 drift detector. Replaces
# the v1.3.25 operator-trust mark-applied UX with a real
# comparison between panel intent (sentinel files + settings) and
# CrowdSec runtime state read from the read-only /crowdsec-state
# mount.
#
# Phases:
#   Scenarios surface
#   1. PATCH disable a scenario via panel  -> sentinel populated
#   2. Wait DRIFT_WAIT seconds (>= drift detector tick)
#   3. GET /api/security/drift             -> scenarios.drift_detected=true
#   4. docker exec setup-appsec.sh         -> CrowdSec sync
#   5. Wait DRIFT_WAIT seconds
#   6. GET /api/security/drift             -> scenarios.drift_detected=false
#
#   AppSec tuning surface
#   7. PATCH inbound_threshold=22 via panel -> sentinel populated
#   8. Wait DRIFT_WAIT seconds
#   9. GET /api/security/drift             -> appsec_tuning.drift_detected=true
#  10. docker exec setup-appsec.sh         -> argos-tuning.yaml regen
#  11. Wait DRIFT_WAIT seconds
#  12. GET /api/security/drift             -> appsec_tuning.drift_detected=false
#
#   Cleanup (trap): re-enable scenario + restore default 15.
#
# Smoke verifies EFFECT (drift seen / cleared) not specs (the
# drift JSON shape). Working agreement v1.3.20+; six-strike
# upstream-pattern memo for context.
#
# Usage:
#   PANEL_BASE_URL=http://localhost:9180 \
#   ARGOS_SESSION_TOKEN=<cookie value> \
#   CROWDSEC_CONTAINER=argos-prod-crowdsec \
#   TEST_SCENARIO=crowdsecurity/CVE-2017-9841 \
#     ./scripts/smoke/drift-detection.sh
#
# Tunables:
#   DRIFT_WAIT     seconds to wait for the next detector tick
#                  (default 65 = 60s tick + 5s buffer)
#   TEST_THRESHOLD integer to PATCH inbound to (default 22; the
#                  v1.3.19 default is 15 so 22 always differs)
#
# Exit codes:
#   0 = both surfaces flip drift_detected on PATCH then clear on
#       setup-appsec.sh
#   1 = some step diverged from expected state
#   2 = setup error (bad defaults, container missing, etc.)

set -euo pipefail

PANEL_BASE_URL="${PANEL_BASE_URL:-http://localhost:9180}"
ARGOS_SESSION_TOKEN="${ARGOS_SESSION_TOKEN:-}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-argos-prod-crowdsec}"
TEST_SCENARIO="${TEST_SCENARIO:-crowdsecurity/CVE-2017-9841}"
TEST_THRESHOLD="${TEST_THRESHOLD:-22}"
DRIFT_WAIT="${DRIFT_WAIT:-65}"

log()  { printf '[smoke/drift-detection] %s\n' "$*"; }
fail() { printf '[smoke/drift-detection] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() {
    printf '[smoke/drift-detection] SETUP: %s\n' "$*" >&2
    exit 2
}

if [ -z "${ARGOS_SESSION_TOKEN}" ]; then
    setup_fail "ARGOS_SESSION_TOKEN required (panel session cookie)"
fi
if ! docker ps --format '{{.Names}}' | grep -qx "${CROWDSEC_CONTAINER}"; then
    setup_fail "container ${CROWDSEC_CONTAINER} is not running"
fi
command -v jq >/dev/null 2>&1 || setup_fail "jq required for JSON assertions"

ENCODED=$(printf '%s' "${TEST_SCENARIO}" | sed 's|/|%2F|g')
SHORT_NAME="${TEST_SCENARIO##*/}"

# Capture pre-test state so cleanup can restore it.
PREV_INBOUND=$(curl -fsS \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    "${PANEL_BASE_URL}/api/security/appsec-tuning" \
    | jq -r '.inbound_threshold')
PREV_OUTBOUND=$(curl -fsS \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    "${PANEL_BASE_URL}/api/security/appsec-tuning" \
    | jq -r '.outbound_threshold')
[ -n "${PREV_INBOUND}" ] && [ -n "${PREV_OUTBOUND}" ] \
    || setup_fail "couldn't read current tuning state"

cleanup() {
    log "cleanup: restore scenario + tuning state"
    curl -fsS -X PATCH \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{"disabled":false}' \
        "${PANEL_BASE_URL}/api/security/scenarios/${ENCODED}" \
        >/dev/null 2>&1 || true
    curl -fsS -X PATCH \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"inbound_threshold\":${PREV_INBOUND},\"outbound_threshold\":${PREV_OUTBOUND}}" \
        "${PANEL_BASE_URL}/api/security/appsec-tuning" \
        >/dev/null 2>&1 || true
    docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh \
        >/dev/null 2>&1 || true
}
trap cleanup EXIT

# get_drift writes the parsed JSON to a tempfile so callers can jq
# multiple keys without re-fetching. Echoes the path.
get_drift() {
    local f
    f=$(mktemp)
    curl -fsS \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        "${PANEL_BASE_URL}/api/security/drift" > "${f}"
    echo "${f}"
}

log "pre-flight: ${TEST_SCENARIO} starts INSTALLED"
if ! docker exec "${CROWDSEC_CONTAINER}" \
       ls "/etc/crowdsec/scenarios/${SHORT_NAME}.yaml" \
       >/dev/null 2>&1; then
    setup_fail "${TEST_SCENARIO} not installed; pick another TEST_SCENARIO"
fi
if [ "${TEST_THRESHOLD}" = "${PREV_INBOUND}" ]; then
    setup_fail "TEST_THRESHOLD (${TEST_THRESHOLD}) equals current inbound (${PREV_INBOUND}); pick a different value"
fi

# === Scenarios surface =======================================
log "[1/12] PATCH disable=true ${TEST_SCENARIO}"
curl -fsS -X PATCH \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"disabled":true}' \
    "${PANEL_BASE_URL}/api/security/scenarios/${ENCODED}" \
    | jq -e '.disabled == true' >/dev/null \
    || fail "PATCH disable did not return disabled=true"

log "[2/12] wait ${DRIFT_WAIT}s for next drift tick"
sleep "${DRIFT_WAIT}"

log "[3/12] expect scenarios.drift_detected=true"
F=$(get_drift)
DETECTED=$(jq -r '.scenarios.drift_detected' "${F}")
ACTUAL=$(jq -r '.scenarios.actually_enabled | join(",")' "${F}")
rm -f "${F}"
[ "${DETECTED}" = "true" ] \
    || fail "expected drift_detected=true after PATCH+wait, got ${DETECTED}"
echo "${ACTUAL}" | grep -qx "${TEST_SCENARIO}" \
    || fail "expected ${TEST_SCENARIO} in actually_enabled, got: ${ACTUAL}"

log "[4/12] run setup-appsec.sh (consume sentinel, remove scenario)"
docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh \
    >/dev/null 2>&1 \
    || fail "setup-appsec.sh exited non-zero on disable path"

log "[5/12] wait ${DRIFT_WAIT}s for next drift tick"
sleep "${DRIFT_WAIT}"

log "[6/12] expect scenarios.drift_detected=false"
F=$(get_drift)
DETECTED=$(jq -r '.scenarios.drift_detected' "${F}")
rm -f "${F}"
[ "${DETECTED}" = "false" ] \
    || fail "expected drift_detected=false after script ran, got ${DETECTED}"

# === AppSec tuning surface ===================================
log "[7/12] PATCH inbound_threshold=${TEST_THRESHOLD} (was ${PREV_INBOUND})"
curl -fsS -X PATCH \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"inbound_threshold\":${TEST_THRESHOLD}}" \
    "${PANEL_BASE_URL}/api/security/appsec-tuning" \
    | jq -e ".inbound_threshold == ${TEST_THRESHOLD}" >/dev/null \
    || fail "PATCH tuning did not echo new value"

log "[8/12] wait ${DRIFT_WAIT}s for next drift tick"
sleep "${DRIFT_WAIT}"

log "[9/12] expect appsec_tuning.drift_detected=true"
F=$(get_drift)
DETECTED=$(jq -r '.appsec_tuning.drift_detected' "${F}")
EXP_IN=$(jq -r '.appsec_tuning.expected_inbound' "${F}")
ACT_IN=$(jq -r '.appsec_tuning.actual_inbound' "${F}")
rm -f "${F}"
[ "${DETECTED}" = "true" ] \
    || fail "expected tuning drift_detected=true, got ${DETECTED}"
[ "${EXP_IN}" = "${TEST_THRESHOLD}" ] \
    || fail "expected_inbound mismatch: ${EXP_IN} != ${TEST_THRESHOLD}"
log "  observed: panel intent=${EXP_IN}, runtime=${ACT_IN}"

log "[10/12] run setup-appsec.sh (regen argos-tuning.yaml)"
docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh \
    >/dev/null 2>&1 \
    || fail "setup-appsec.sh exited non-zero on tuning path"

log "[11/12] wait ${DRIFT_WAIT}s for next drift tick"
sleep "${DRIFT_WAIT}"

log "[12/12] expect appsec_tuning.drift_detected=false"
F=$(get_drift)
DETECTED=$(jq -r '.appsec_tuning.drift_detected' "${F}")
ACT_IN=$(jq -r '.appsec_tuning.actual_inbound' "${F}")
rm -f "${F}"
[ "${DETECTED}" = "false" ] \
    || fail "expected tuning drift_detected=false after regen, got ${DETECTED}"
[ "${ACT_IN}" = "${TEST_THRESHOLD}" ] \
    || fail "actual_inbound never reflected new threshold: ${ACT_IN}"

log "PASS: drift detector flips + clears for both surfaces"
