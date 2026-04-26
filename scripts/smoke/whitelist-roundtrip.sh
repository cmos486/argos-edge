#!/bin/bash
# scripts/smoke/whitelist-roundtrip.sh
#
# v1.3.32 verification smoke: manual whitelist UI -> sentinel ->
# CrowdSec parser config round-trip.
#
# Phases:
#   1. POST /api/security/whitelist {scope:ip,value:198.51.100.42}
#   2. GET /api/security/whitelist contains the new entry
#   3. /shared/argos-whitelist-entries.txt sentinel updated
#   4. setup-appsec.sh inside crowdsec
#   5. /etc/crowdsec/parsers/s02-enrich/argos-whitelist.yaml
#      contains the IP under the ip: list
#   6. DELETE /api/security/whitelist/{id}
#   7. GET shows entry gone
#   8. setup-appsec.sh again; assert IP gone from yaml
#
# Smoke verifies EFFECT (per the working agreement v1.3.20+):
# the panel really persists the whitelist row, the sentinel
# really updates, the script really regenerates the parser
# config, and the inverse cleanup path works too.
#
# TEST_IP defaults to 198.51.100.42 (RFC 5737 documentation
# range, never a real source).
#
# Usage:
#   PANEL_BASE_URL=http://localhost:9180 \
#   ARGOS_SESSION_TOKEN=<cookie value> \
#   CROWDSEC_CONTAINER=argos-prod-crowdsec \
#     ./scripts/smoke/whitelist-roundtrip.sh
#
# Exit codes:
#   0 = full round-trip works
#   1 = an assertion diverged
#   2 = setup error

set -euo pipefail

PANEL_BASE_URL="${PANEL_BASE_URL:-http://localhost:9180}"
ARGOS_SESSION_TOKEN="${ARGOS_SESSION_TOKEN:-}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-argos-prod-crowdsec}"
TEST_IP="${TEST_IP:-198.51.100.42}"

log()  { printf '[smoke/whitelist] %s\n' "$*"; }
fail() { printf '[smoke/whitelist] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() {
    printf '[smoke/whitelist] SETUP: %s\n' "$*" >&2
    exit 2
}

[ -n "${ARGOS_SESSION_TOKEN}" ] || setup_fail "ARGOS_SESSION_TOKEN required"
docker ps --format '{{.Names}}' | grep -qx "${CROWDSEC_CONTAINER}" \
    || setup_fail "container ${CROWDSEC_CONTAINER} not running"
command -v jq >/dev/null 2>&1 || setup_fail "jq required"

ENTRY_ID=""

cleanup() {
    if [ -n "${ENTRY_ID}" ]; then
        log "cleanup: DELETE /security/whitelist/${ENTRY_ID}"
        curl -fsS -X DELETE \
            -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
            "${PANEL_BASE_URL}/api/security/whitelist/${ENTRY_ID}" \
            >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# Pre-cleanup: any prior smoke run that died mid-flight may have
# left ${TEST_IP} in the table. Sweep first so the duplicate-add
# 409 doesn't tank phase 1.
log "pre-flight: sweep any prior ${TEST_IP} whitelist entries"
curl -fsS \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    "${PANEL_BASE_URL}/api/security/whitelist" 2>/dev/null \
    | jq -r --arg ip "${TEST_IP}" \
        '.entries[] | select(.value == $ip) | .id' \
    | while read -r oldID; do
        [ -n "${oldID}" ] && curl -fsS -X DELETE \
            -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
            "${PANEL_BASE_URL}/api/security/whitelist/${oldID}" \
            >/dev/null 2>&1 || true
    done

# === phase 1: POST /api/security/whitelist ====================
log "[1/8] POST /api/security/whitelist (ip ${TEST_IP})"
ADD_RESP=$(curl -fsS -X POST \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"scope\":\"ip\",\"value\":\"${TEST_IP}\",\"reason\":\"smoke verification\"}" \
    "${PANEL_BASE_URL}/api/security/whitelist")
log "  add response: ${ADD_RESP}"

# === phase 2: GET shows entry =================================
log "[2/8] GET /api/security/whitelist contains ${TEST_IP}"
LIST=$(curl -fsS -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    "${PANEL_BASE_URL}/api/security/whitelist")
ENTRY_ID=$(echo "${LIST}" | jq -r --arg ip "${TEST_IP}" \
    '.entries[] | select(.value == $ip) | .id' | head -1)
[ -n "${ENTRY_ID}" ] && [ "${ENTRY_ID}" != "null" ] \
    || fail "${TEST_IP} not in list after add: ${LIST}"
log "  entry_id=${ENTRY_ID}"

# === phase 3: sentinel updated ================================
log "[3/8] /shared/argos-whitelist-entries.txt contains ${TEST_IP}"
docker exec "${CROWDSEC_CONTAINER}" \
    cat /shared/argos-whitelist-entries.txt 2>/dev/null \
    | grep -qF "ip ${TEST_IP}" \
    || fail "sentinel does not contain 'ip ${TEST_IP}'"

# === phase 4: run setup-appsec.sh =============================
log "[4/8] run setup-appsec.sh inside ${CROWDSEC_CONTAINER}"
docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh >/dev/null 2>&1 || true

# === phase 5: parser yaml has the IP ==========================
log "[5/8] /etc/crowdsec/parsers/s02-enrich/argos-whitelist.yaml contains ${TEST_IP}"
docker exec "${CROWDSEC_CONTAINER}" \
    cat /etc/crowdsec/parsers/s02-enrich/argos-whitelist.yaml 2>/dev/null \
    | grep -qF "${TEST_IP}" \
    || fail "argos-whitelist.yaml does not contain ${TEST_IP}"
log "  parser config has the IP"

# === phase 6: DELETE ==========================================
log "[6/8] DELETE /api/security/whitelist/${ENTRY_ID}"
curl -fsS -X DELETE \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    "${PANEL_BASE_URL}/api/security/whitelist/${ENTRY_ID}" \
    >/dev/null
SAVED_ID="${ENTRY_ID}"
ENTRY_ID=""  # disable cleanup

# === phase 7: GET shows entry gone ============================
log "[7/8] GET /api/security/whitelist no longer contains ${TEST_IP}"
LIST_AFTER=$(curl -fsS -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    "${PANEL_BASE_URL}/api/security/whitelist")
echo "${LIST_AFTER}" | jq -e --arg ip "${TEST_IP}" \
    '.entries | all(.value != $ip)' >/dev/null \
    || fail "${TEST_IP} still in list after delete"

# === phase 8: setup-appsec.sh + parser yaml clean =============
log "[8/8] post-delete setup-appsec.sh + parser yaml lacks ${TEST_IP}"
docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh >/dev/null 2>&1 || true
if docker exec "${CROWDSEC_CONTAINER}" \
       cat /etc/crowdsec/parsers/s02-enrich/argos-whitelist.yaml 2>/dev/null \
       | grep -qF "${TEST_IP}"; then
    fail "argos-whitelist.yaml still contains ${TEST_IP} after delete + reload"
fi

log "PASS: whitelist round-trip end-to-end (panel -> sentinel -> parser yaml)"
