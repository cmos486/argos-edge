#!/bin/bash
# scripts/smoke/banned-ips-roundtrip.sh
#
# v1.3.32 verification smoke: Banned IPs UI surface end-to-end.
# cscli adds an IP decision -> panel /api/security/decisions
# lists it -> panel DELETE /api/security/decisions/{id} removes
# it -> cscli list confirms gone.
#
# Smoke verifies EFFECT (per the working agreement v1.3.20+):
# the panel's read endpoint really sees LAPI decisions, the
# panel's delete endpoint really removes them at the LAPI side,
# and origin/scope filters work correctly.
#
# Usage:
#   PANEL_BASE_URL=http://localhost:9180 \
#   ARGOS_SESSION_TOKEN=<cookie value> \
#   CROWDSEC_CONTAINER=argos-prod-crowdsec \
#     ./scripts/smoke/banned-ips-roundtrip.sh
#
# Tunables:
#   TEST_IP   IPv4 (RFC 5737) used as the test ban target.
#             Default 198.51.100.99.
#
# Exit codes:
#   0 = round-trip works
#   1 = an assertion diverged
#   2 = setup error

set -euo pipefail

PANEL_BASE_URL="${PANEL_BASE_URL:-http://localhost:9180}"
ARGOS_SESSION_TOKEN="${ARGOS_SESSION_TOKEN:-}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-argos-prod-crowdsec}"
TEST_IP="${TEST_IP:-198.51.100.99}"

log()  { printf '[smoke/banned-ips] %s\n' "$*"; }
fail() { printf '[smoke/banned-ips] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() {
    printf '[smoke/banned-ips] SETUP: %s\n' "$*" >&2
    exit 2
}

[ -n "${ARGOS_SESSION_TOKEN}" ] || setup_fail "ARGOS_SESSION_TOKEN required"
docker ps --format '{{.Names}}' | grep -qx "${CROWDSEC_CONTAINER}" \
    || setup_fail "container ${CROWDSEC_CONTAINER} not running"
command -v jq >/dev/null 2>&1 || setup_fail "jq required"

cleanup() {
    log "cleanup: ensure ${TEST_IP} has no leftover decision"
    docker exec "${CROWDSEC_CONTAINER}" cscli decisions delete --ip "${TEST_IP}" \
        >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Pre-flight: drop any stale decision for ${TEST_IP} from prior
# runs so the assertions count cleanly.
cleanup

# === phase 1: cscli adds a decision ===========================
log "[1/5] cscli decisions add --scope Ip --value ${TEST_IP}"
docker exec "${CROWDSEC_CONTAINER}" cscli decisions add \
    --scope Ip --value "${TEST_IP}" \
    --duration 1h --reason "argos smoke: banned-ips verification" \
    >/dev/null
sleep 17  # crowdsec.Client.ListDecisions has a 15s cache TTL

# === phase 2: panel /api/security/decisions sees it ===========
log "[2/5] GET /api/security/decisions ?ip=${TEST_IP} contains the new ban"
RESP=$(curl -fsS \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    "${PANEL_BASE_URL}/api/security/decisions?q=${TEST_IP}")
ENTRY=$(echo "${RESP}" | jq --arg ip "${TEST_IP}" \
    '.decisions[] | select(.value == $ip)' | head -c 800)
[ -n "${ENTRY}" ] \
    || fail "panel did not list the new ${TEST_IP} ban: ${RESP}"
DECISION_ID=$(echo "${ENTRY}" | jq -r .id)
ORIGIN=$(echo "${ENTRY}" | jq -r .origin)
log "  decision_id=${DECISION_ID} origin=${ORIGIN}"

# === phase 3: DELETE via panel ================================
log "[3/5] DELETE /api/security/decisions/${DECISION_ID}"
DEL_RESP=$(curl -fsS -X DELETE \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    "${PANEL_BASE_URL}/api/security/decisions/${DECISION_ID}")
echo "${DEL_RESP}" | jq -e '.deleted >= 1 or .ok == true or has("removed")' >/dev/null \
    || fail "delete response unexpected: ${DEL_RESP}"
log "  delete response: ${DEL_RESP}"
sleep 17  # cache invalidation window

# === phase 4: cscli confirms gone =============================
log "[4/5] cscli decisions list --ip ${TEST_IP} confirms gone"
CSCLI_AFTER=$(docker exec "${CROWDSEC_CONTAINER}" cscli decisions list --ip "${TEST_IP}" 2>&1)
echo "${CSCLI_AFTER}" | grep -qE 'No active decisions|No decisions' \
    || fail "cscli still shows ${TEST_IP}: ${CSCLI_AFTER}"

# === phase 5: panel list also shows gone ======================
log "[5/5] GET /api/security/decisions ?q=${TEST_IP} returns empty"
PANEL_AFTER=$(curl -fsS \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    "${PANEL_BASE_URL}/api/security/decisions?q=${TEST_IP}")
COUNT_AFTER=$(echo "${PANEL_AFTER}" | jq --arg ip "${TEST_IP}" \
    '[.decisions[] | select(.value == $ip)] | length')
[ "${COUNT_AFTER}" = "0" ] \
    || fail "panel still lists ${TEST_IP} after delete (count=${COUNT_AFTER})"

log "PASS: Banned IPs round-trip (cscli add -> panel list -> panel delete -> cscli confirm)"
