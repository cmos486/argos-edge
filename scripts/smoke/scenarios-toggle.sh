#!/bin/bash
# scripts/smoke/scenarios-toggle.sh
#
# End-to-end verification of the v1.3.25 scenarios management
# UI: panel PATCH disable → sentinel populated → setup-appsec.sh
# reload → cscli scenarios list confirms scenario gone → panel
# PATCH re-enable → setup-appsec.sh reload → cscli confirms
# scenario back → cleanup.
#
# Exists because v1.3.25 prod-smoke caught a deploy gap (the
# operational dir's setup-appsec.sh was stale relative to the
# repo source; the CrowdSec container bind-mounts from the
# operational dir). Asserting just on the panel emit ("sentinel
# was written") missed the second half of the chain (the script
# actually applies it, cscli reflects the intended state). This
# script automates the full chain so the v1.3.25 working-
# agreement smoke gate can pass without operator handoff.
#
# Usage:
#   PANEL_BASE_URL=http://localhost:9180 \
#   ARGOS_SESSION_TOKEN=<cookie value> \
#   CROWDSEC_CONTAINER=argos-prod-crowdsec \
#   TEST_SCENARIO=crowdsecurity/CVE-2017-9841 \
#     ./scripts/smoke/scenarios-toggle.sh
#
# Defaults are placeholders that refuse to run; the operator
# overrides every variable to match their stack.
#
# Exit codes:
#   0 = full toggle round-trip works
#   1 = some step diverged from expected state
#   2 = setup error (bad defaults, missing container, etc.)

set -euo pipefail

PANEL_BASE_URL="${PANEL_BASE_URL:-http://localhost:9180}"
ARGOS_SESSION_TOKEN="${ARGOS_SESSION_TOKEN:-}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-argos-prod-crowdsec}"
TEST_SCENARIO="${TEST_SCENARIO:-crowdsecurity/CVE-2017-9841}"

log()  { printf '[smoke/scenarios-toggle] %s\n' "$*"; }
fail() { printf '[smoke/scenarios-toggle] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() {
    printf '[smoke/scenarios-toggle] SETUP: %s\n' "$*" >&2
    exit 2
}

if [ -z "${ARGOS_SESSION_TOKEN}" ]; then
    setup_fail "ARGOS_SESSION_TOKEN required (panel session cookie)"
fi
if ! docker ps --format '{{.Names}}' | grep -qx "${CROWDSEC_CONTAINER}"; then
    setup_fail "container ${CROWDSEC_CONTAINER} is not running"
fi

# URL-encode the slash in the canonical scenario name. chi v5
# captures path segments without auto-decoding; the panel handler
# url.PathUnescape's the param to recover the canonical form.
ENCODED=$(printf '%s' "${TEST_SCENARIO}" | sed 's|/|%2F|g')
SHORT_NAME="${TEST_SCENARIO##*/}"

cleanup() {
    log "cleanup: re-enable ${TEST_SCENARIO} via panel + reload"
    curl -fsS -X PATCH \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{"disabled":false}' \
        "${PANEL_BASE_URL}/api/security/scenarios/${ENCODED}" \
        >/dev/null 2>&1 || true
    docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh \
        >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "[1/8] sanity: ${TEST_SCENARIO} starts INSTALLED"
if ! docker exec "${CROWDSEC_CONTAINER}" \
       ls "/etc/crowdsec/scenarios/${SHORT_NAME}.yaml" \
       >/dev/null 2>&1; then
    setup_fail "${TEST_SCENARIO} not installed; pick another TEST_SCENARIO"
fi

log "[2/8] PATCH disable=true via panel"
RESP=$(curl -fsS -X PATCH \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"disabled":true}' \
    "${PANEL_BASE_URL}/api/security/scenarios/${ENCODED}")
echo "${RESP}" | grep -q '"disabled":true' \
    || fail "PATCH did not return disabled=true: ${RESP}"

log "[3/8] verify panel-managed sentinel populated"
SENTINEL_CONTENT=$(docker exec "${CROWDSEC_CONTAINER}" \
    cat /shared/argos-disabled-scenarios.txt 2>/dev/null \
    | grep -v '^#' | grep -v '^$')
echo "${SENTINEL_CONTENT}" | grep -qx "${TEST_SCENARIO}" \
    || fail "sentinel does not contain ${TEST_SCENARIO}: ${SENTINEL_CONTENT}"

log "[4/8] run setup-appsec.sh inside crowdsec"
docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh \
    >/dev/null 2>&1 \
    || fail "setup-appsec.sh exited non-zero on disable path"

log "[5/8] verify scenario actually removed from /etc/crowdsec"
if docker exec "${CROWDSEC_CONTAINER}" \
       ls "/etc/crowdsec/scenarios/${SHORT_NAME}.yaml" \
       >/dev/null 2>&1; then
    fail "${SHORT_NAME}.yaml still present after disable + reload"
fi

log "[6/8] PATCH disable=false (re-enable) via panel"
RESP=$(curl -fsS -X PATCH \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"disabled":false}' \
    "${PANEL_BASE_URL}/api/security/scenarios/${ENCODED}")
echo "${RESP}" | grep -q '"disabled":false' \
    || fail "PATCH did not return disabled=false: ${RESP}"

log "[7/8] run setup-appsec.sh again (collection refresh path)"
docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh \
    >/dev/null 2>&1 \
    || fail "setup-appsec.sh exited non-zero on re-enable path"

log "[8/8] verify scenario came back"
if ! docker exec "${CROWDSEC_CONTAINER}" \
       ls "/etc/crowdsec/scenarios/${SHORT_NAME}.yaml" \
       >/dev/null 2>&1; then
    fail "${SHORT_NAME}.yaml not restored after re-enable + reload"
fi

log "PASS: scenarios toggle round-trip verified end-to-end"
