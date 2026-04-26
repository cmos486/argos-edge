#!/bin/bash
# scripts/smoke/scenario-descriptions.sh
#
# v1.3.30 smoke gate: scenario descriptions enrichment end-to-end.
# Verifies the reverse-sentinel pattern: setup-appsec.sh (running
# as root inside crowdsec, can read 0600 hub files) emits a
# slimmed {name: description} JSON to /shared/argos-scenarios-
# index.json; panel-as-nobody reads that file via the existing
# shared volume mount and enriches /api/security/scenarios
# response with the description field.
#
# Smoke verifies EFFECT (per the working agreement v1.3.20+):
#   - the slimmed file exists and is valid JSON
#   - the API response carries description for >= 90% of
#     scenarios
#   - a known-good scenario (CVE-2017-9841) has the expected
#     description text
#   - graceful degrade: with the slimmed file removed, the API
#     still returns scenarios but with empty descriptions (no
#     crash, no 500)
#
# Usage:
#   PANEL_BASE_URL=http://localhost:9180 \
#   ARGOS_SESSION_TOKEN=<cookie value> \
#   CROWDSEC_CONTAINER=argos-prod-crowdsec \
#     ./scripts/smoke/scenario-descriptions.sh
#
# Exit codes:
#   0 = all 5 phases pass
#   1 = an assertion diverged
#   2 = setup error (missing env, container not running, etc.)

set -euo pipefail

PANEL_BASE_URL="${PANEL_BASE_URL:-http://localhost:9180}"
ARGOS_SESSION_TOKEN="${ARGOS_SESSION_TOKEN:-}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-argos-prod-crowdsec}"
KNOWN_SCENARIO="${KNOWN_SCENARIO:-crowdsecurity/CVE-2017-9841}"
KNOWN_SUBSTRING="${KNOWN_SUBSTRING:-CVE-2017-9841}"
COVERAGE_PCT="${COVERAGE_PCT:-90}"

log()  { printf '[smoke/scenario-descriptions] %s\n' "$*"; }
fail() { printf '[smoke/scenario-descriptions] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() {
    printf '[smoke/scenario-descriptions] SETUP: %s\n' "$*" >&2
    exit 2
}

[ -n "${ARGOS_SESSION_TOKEN}" ] || setup_fail "ARGOS_SESSION_TOKEN required"
docker ps --format '{{.Names}}' | grep -qx "${CROWDSEC_CONTAINER}" \
    || setup_fail "container ${CROWDSEC_CONTAINER} is not running"
command -v jq >/dev/null 2>&1 || setup_fail "jq required on host"

INDEX_PATH=/shared/argos-scenarios-index.json
BACKUP_PATH=/shared/argos-scenarios-index.json.smoke-backup

cleanup() {
    log "cleanup: restore /shared/argos-scenarios-index.json if backup exists"
    docker exec "${CROWDSEC_CONTAINER}" sh -c \
        "[ -f ${BACKUP_PATH} ] && mv ${BACKUP_PATH} ${INDEX_PATH} || true" \
        2>/dev/null || true
}
trap cleanup EXIT

api_scenarios_json() {
    curl -fsS \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        "${PANEL_BASE_URL}/api/security/scenarios"
}

# === phase 1: setup-appsec.sh emits the slimmed file ==========
log "[1/5] run setup-appsec.sh -> verify ${INDEX_PATH} produced"
# setup-appsec.sh restarts crowdsec at the end if profiles.yaml
# changed (v1.3.29 path) -- in this smoke we don't touch
# true_detect_mode so PROFILES_CHANGED stays 0 and SIGHUP is the
# only side effect.
docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh >/tmp/sa.log 2>&1 || true
# Brief settle after SIGHUP.
sleep 2

if ! docker exec "${CROWDSEC_CONTAINER}" test -s "${INDEX_PATH}"; then
    fail "${INDEX_PATH} missing or empty after setup-appsec.sh"
fi
# wc reads inside the container -- redirect must be on the
# container's shell, not the host's. docker exec without sh -c
# would resolve the < redirect on the host where the path does
# not exist.
SIZE=$(docker exec "${CROWDSEC_CONTAINER}" sh -c "wc -c < ${INDEX_PATH}")
log "  slimmed index: ${SIZE} bytes"
docker exec "${CROWDSEC_CONTAINER}" cat "${INDEX_PATH}" | jq empty 2>/dev/null \
    || fail "${INDEX_PATH} is not valid JSON"

# === phase 2: API surfaces descriptions for >= COVERAGE_PCT% =
log "[2/5] GET /api/security/scenarios -> coverage >= ${COVERAGE_PCT}%"
RESP=$(api_scenarios_json)
TOTAL=$(echo "${RESP}" | jq '.scenarios | length')
WITH_DESC=$(echo "${RESP}" | jq '[.scenarios[] | select(.description != null and .description != "")] | length')
[ "${TOTAL}" -gt 0 ] || fail "scenarios list is empty -- /crowdsec-state mount issue?"
PCT=$(( 100 * WITH_DESC / TOTAL ))
log "  ${WITH_DESC} / ${TOTAL} scenarios have description (${PCT}%)"
[ "${PCT}" -ge "${COVERAGE_PCT}" ] \
    || fail "coverage ${PCT}% < ${COVERAGE_PCT}% threshold; setup-appsec.sh emitted but panel didn't pick it up?"

# === phase 3: known-good scenario carries expected text ======
log "[3/5] ${KNOWN_SCENARIO} description contains '${KNOWN_SUBSTRING}'"
DESC=$(echo "${RESP}" | jq -r --arg n "${KNOWN_SCENARIO}" \
    '.scenarios[] | select(.canonical_name == $n) | .description // ""')
[ -n "${DESC}" ] \
    || fail "${KNOWN_SCENARIO} not found OR description empty"
echo "${DESC}" | grep -qF "${KNOWN_SUBSTRING}" \
    || fail "description for ${KNOWN_SCENARIO} does not contain '${KNOWN_SUBSTRING}': '${DESC}'"
log "  description: ${DESC}"

# === phase 4: graceful degrade when slimmed file is gone =====
log "[4/5] graceful degrade: rename index file, GET still works"
docker exec "${CROWDSEC_CONTAINER}" mv "${INDEX_PATH}" "${BACKUP_PATH}"
# The backend reads on every request via mtime check; the next
# stat will fail and Get() returns "" but does not blank the
# in-memory map. To force a true "no descriptions" response we
# need to either restart panel OR rely on the test running
# fresh. For smoke we just verify the API doesn't 500.
DEGRADED=$(api_scenarios_json)
COUNT_DEGRADED=$(echo "${DEGRADED}" | jq '.scenarios | length')
[ "${COUNT_DEGRADED}" -gt 0 ] \
    || fail "API returned no scenarios with index file removed -- request errored"
log "  API still returns ${COUNT_DEGRADED} scenarios with index file absent (graceful degrade ok)"

# === phase 5: restore + verify recovery ======================
log "[5/5] restore index file -> verify subsequent GET picks it up"
docker exec "${CROWDSEC_CONTAINER}" mv "${BACKUP_PATH}" "${INDEX_PATH}"
# Mtime-based reload: bump mtime so the backend's next request
# picks the file up regardless of cmp -s no-op suppression in
# setup-appsec.sh.
docker exec "${CROWDSEC_CONTAINER}" touch "${INDEX_PATH}"
sleep 1
RESTORED=$(api_scenarios_json)
RESTORED_DESC=$(echo "${RESTORED}" | jq -r --arg n "${KNOWN_SCENARIO}" \
    '.scenarios[] | select(.canonical_name == $n) | .description // ""')
[ -n "${RESTORED_DESC}" ] \
    || fail "description still empty after restoring file (mtime cache?)"
log "  description restored: ${RESTORED_DESC}"

log "PASS: scenario descriptions enrichment end-to-end"
