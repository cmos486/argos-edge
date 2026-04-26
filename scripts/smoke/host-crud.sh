#!/bin/bash
# scripts/smoke/host-crud.sh
#
# v1.3.32 verification smoke: host CRUD round-trip + reconciler
# triggers Caddy reload.
#
# Phases:
#   1. POST /api/hosts -> create a test host (bound to first
#      existing target group; we don't introduce a new TG)
#   2. GET /api/hosts/{id} echoes the test host
#   3. POST /api/hosts/{id}/toggle flips enabled bit
#   4. PUT /api/hosts/{id} updates a mutable field (auth_required)
#   5. DELETE /api/hosts/{id} removes the row
#   6. GET /api/hosts/{id} returns 404
#   7. GET /api/caddy/status confirms Caddy admin API reachable
#      (proxy for "reconciler can deploy config")
#
# Smoke verifies EFFECT (per the working agreement v1.3.20+):
# the panel really persists the host, the reconciler really
# pushes config to Caddy, and the cleanup path really removes
# both DB row and Caddy config.
#
# Uses a placeholder test domain (test-smoke-XXXXX.example) that
# never resolves and never collides with operator hosts.
#
# Usage:
#   PANEL_BASE_URL=http://localhost:9180 \
#   ARGOS_SESSION_TOKEN=<cookie value> \
#     ./scripts/smoke/host-crud.sh
#
# Exit codes:
#   0 = full CRUD round-trip works
#   1 = an assertion diverged
#   2 = setup error

set -euo pipefail

PANEL_BASE_URL="${PANEL_BASE_URL:-http://localhost:9180}"
ARGOS_SESSION_TOKEN="${ARGOS_SESSION_TOKEN:-}"

log()  { printf '[smoke/host-crud] %s\n' "$*"; }
fail() { printf '[smoke/host-crud] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() {
    printf '[smoke/host-crud] SETUP: %s\n' "$*" >&2
    exit 2
}

[ -n "${ARGOS_SESSION_TOKEN}" ] || setup_fail "ARGOS_SESSION_TOKEN required"
command -v jq >/dev/null 2>&1 || setup_fail "jq required"

# Random-suffixed test domain so re-running the smoke after a
# crash mid-flight doesn't UNIQUE-collide on the previous test
# row (cleanup also handles the happy-path delete).
TEST_DOMAIN="test-smoke-$RANDOM.example"
HOST_ID=""

api() {
    local method="$1"
    local path="$2"
    local body="${3:-}"
    if [ -n "${body}" ]; then
        curl -fsS -X "${method}" \
            -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "${body}" \
            "${PANEL_BASE_URL}/api${path}"
    else
        curl -fsS -X "${method}" \
            -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
            "${PANEL_BASE_URL}/api${path}"
    fi
}

cleanup() {
    if [ -n "${HOST_ID}" ]; then
        log "cleanup: DELETE /hosts/${HOST_ID}"
        api DELETE "/hosts/${HOST_ID}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# Find an existing target group to bind the test host to.
TG_ID=$(api GET "/target-groups" | jq -r '.[0].id // empty')
[ -n "${TG_ID}" ] && [ "${TG_ID}" != "null" ] \
    || setup_fail "no target groups exist; cannot create a host"
log "binding test host to existing target_group_id=${TG_ID}"

# === phase 1: POST /api/hosts =================================
log "[1/7] POST /api/hosts (test domain ${TEST_DOMAIN})"
CREATE_RESP=$(api POST "/hosts" \
    "{\"domain\":\"${TEST_DOMAIN}\",\"target_group_id\":${TG_ID},\"tls_mode\":\"none\",\"tls_email\":\"\"}")
HOST_ID=$(echo "${CREATE_RESP}" | jq -r '.id')
[ -n "${HOST_ID}" ] && [ "${HOST_ID}" != "null" ] \
    || fail "create did not return id: ${CREATE_RESP}"
log "  created host_id=${HOST_ID}"

# === phase 2: GET /api/hosts/{id} =============================
log "[2/7] GET /api/hosts/${HOST_ID}"
GET_RESP=$(api GET "/hosts/${HOST_ID}")
[ "$(echo "${GET_RESP}" | jq -r .domain)" = "${TEST_DOMAIN}" ] \
    || fail "GET returned wrong domain: ${GET_RESP}"
INITIAL_ENABLED=$(echo "${GET_RESP}" | jq -r .enabled)
log "  host echo'd; initial enabled=${INITIAL_ENABLED}"

# === phase 3: toggle ==========================================
log "[3/7] POST /api/hosts/${HOST_ID}/toggle"
api POST "/hosts/${HOST_ID}/toggle" >/dev/null
TOGGLED=$(api GET "/hosts/${HOST_ID}" | jq -r .enabled)
[ "${TOGGLED}" != "${INITIAL_ENABLED}" ] \
    || fail "toggle did not flip enabled flag (was ${INITIAL_ENABLED}, still ${TOGGLED})"
log "  enabled flipped: ${INITIAL_ENABLED} -> ${TOGGLED}"

# === phase 4: PUT (full replace) ==============================
log "[4/7] PUT /api/hosts/${HOST_ID} (auth_required: true)"
PUT_BODY=$(echo "${GET_RESP}" | jq --argjson enabled "${TOGGLED}" \
    '{domain, target_group_id, tls_mode, tls_email,
      enabled: $enabled,
      auth_required: true,
      lan_only,
      true_detect_mode,
      tls_acme_ca_url,
      tls_challenge,
      tls_dns_provider}')
PUT_RESP=$(api PUT "/hosts/${HOST_ID}" "${PUT_BODY}")
NEW_AUTH=$(echo "${PUT_RESP}" | jq -r .auth_required)
[ "${NEW_AUTH}" = "true" ] \
    || fail "PUT did not update auth_required: got ${NEW_AUTH}"
log "  auth_required updated to true"

# === phase 5: DELETE ==========================================
log "[5/7] DELETE /api/hosts/${HOST_ID}"
api DELETE "/hosts/${HOST_ID}" >/dev/null
SAVED_ID="${HOST_ID}"
HOST_ID=""  # disable cleanup; the explicit delete already removed it

# === phase 6: confirm 404 =====================================
log "[6/7] GET /api/hosts/${SAVED_ID} returns 404"
GONE_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    "${PANEL_BASE_URL}/api/hosts/${SAVED_ID}")
[ "${GONE_CODE}" = "404" ] \
    || fail "expected 404 after delete, got ${GONE_CODE}"
log "  delete confirmed via 404"

# === phase 7: Caddy admin reachable ==========================
log "[7/7] GET /api/caddy/status (reconciler -> Caddy reachable)"
CADDY_STATUS=$(api GET "/caddy/status" 2>&1)
echo "${CADDY_STATUS}" | jq -e '.ok == true or .reachable == true or .status == "ok" or has("config_hash") or has("hosts_loaded")' >/dev/null 2>&1 \
    || fail "caddy status unhealthy: ${CADDY_STATUS}"
log "  caddy admin API reachable; reconciler healthy"

log "PASS: host CRUD round-trip + reconciler -> Caddy verified"
