#!/bin/bash
# scripts/smoke/appsec-tuning.sh
#
# End-to-end verification of the v1.3.25 AppSec threshold tuning
# UI: panel PATCH inbound_threshold N → sentinel populated →
# setup-appsec.sh reload → /etc/crowdsec/appsec-rules/argos-
# tuning.yaml regenerated with the new value → restore → reload
# again.
#
# Companion to scripts/smoke/scenarios-toggle.sh; same rationale
# (v1.3.25 prod-smoke caught a deploy gap; the script-reload
# half of the chain wasn't being asserted before tag).
#
# Usage:
#   PANEL_BASE_URL=http://localhost:9180 \
#   ARGOS_SESSION_TOKEN=<cookie value> \
#   CROWDSEC_CONTAINER=argos-prod-crowdsec \
#     ./scripts/smoke/appsec-tuning.sh
#
# Asserts the inbound_threshold round-trip 15 → 12 → 15. Outbound
# stays untouched in this script (the YAML write is identical
# code; testing one is enough to verify the regeneration path).
#
# Exit codes:
#   0 = round-trip works
#   1 = state diverged
#   2 = setup error

set -euo pipefail

PANEL_BASE_URL="${PANEL_BASE_URL:-http://localhost:9180}"
ARGOS_SESSION_TOKEN="${ARGOS_SESSION_TOKEN:-}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-argos-prod-crowdsec}"
TEST_INBOUND="${TEST_INBOUND:-12}"
DEFAULT_INBOUND="${DEFAULT_INBOUND:-15}"

log()  { printf '[smoke/appsec-tuning] %s\n' "$*"; }
fail() { printf '[smoke/appsec-tuning] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() {
    printf '[smoke/appsec-tuning] SETUP: %s\n' "$*" >&2
    exit 2
}

if [ -z "${ARGOS_SESSION_TOKEN}" ]; then
    setup_fail "ARGOS_SESSION_TOKEN required (panel session cookie)"
fi
if ! docker ps --format '{{.Names}}' | grep -qx "${CROWDSEC_CONTAINER}"; then
    setup_fail "container ${CROWDSEC_CONTAINER} is not running"
fi
if [ "${TEST_INBOUND}" = "${DEFAULT_INBOUND}" ]; then
    setup_fail "TEST_INBOUND must differ from DEFAULT_INBOUND"
fi

cleanup() {
    log "cleanup: restore inbound_threshold=${DEFAULT_INBOUND} + reload"
    curl -fsS -X PATCH \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"inbound_threshold\":${DEFAULT_INBOUND}}" \
        "${PANEL_BASE_URL}/api/security/appsec-tuning" \
        >/dev/null 2>&1 || true
    docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh \
        >/dev/null 2>&1 || true
}
trap cleanup EXIT

YAML_PATH=/etc/crowdsec/appsec-rules/argos-tuning.yaml

log "[1/6] PATCH inbound_threshold=${TEST_INBOUND} via panel"
RESP=$(curl -fsS -X PATCH \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"inbound_threshold\":${TEST_INBOUND}}" \
    "${PANEL_BASE_URL}/api/security/appsec-tuning")
echo "${RESP}" | grep -q "\"inbound_threshold\":${TEST_INBOUND}" \
    || fail "PATCH did not return new value: ${RESP}"

log "[2/6] verify panel sentinel"
SENTINEL=$(docker exec "${CROWDSEC_CONTAINER}" \
    cat /shared/argos-appsec-tuning.txt 2>/dev/null)
echo "${SENTINEL}" | grep -qx "inbound_threshold=${TEST_INBOUND}" \
    || fail "sentinel does not carry inbound_threshold=${TEST_INBOUND}"

log "[3/6] run setup-appsec.sh inside crowdsec"
docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh \
    >/dev/null 2>&1 \
    || fail "setup-appsec.sh exited non-zero"

log "[4/6] verify regenerated argos-tuning.yaml has new threshold"
YAML_CONTENT=$(docker exec "${CROWDSEC_CONTAINER}" \
    cat "${YAML_PATH}" 2>/dev/null)
echo "${YAML_CONTENT}" \
    | grep -q "tx.inbound_anomaly_score_threshold=${TEST_INBOUND}" \
    || fail "argos-tuning.yaml missing inbound_anomaly_score_threshold=${TEST_INBOUND}: ${YAML_CONTENT}"

log "[5/6] PATCH back to default ${DEFAULT_INBOUND}"
curl -fsS -X PATCH \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"inbound_threshold\":${DEFAULT_INBOUND}}" \
    "${PANEL_BASE_URL}/api/security/appsec-tuning" >/dev/null

docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh \
    >/dev/null 2>&1 \
    || fail "setup-appsec.sh failed on restore path"

log "[6/6] verify yaml restored"
RESTORED=$(docker exec "${CROWDSEC_CONTAINER}" \
    grep "tx.inbound_anomaly_score_threshold" "${YAML_PATH}")
echo "${RESTORED}" \
    | grep -q "=${DEFAULT_INBOUND}" \
    || fail "yaml not restored to ${DEFAULT_INBOUND}: ${RESTORED}"

log "PASS: appsec-tuning round-trip verified end-to-end"
