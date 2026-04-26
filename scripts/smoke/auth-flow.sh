#!/bin/bash
# scripts/smoke/auth-flow.sh
#
# v1.3.32 verification smoke: authentication lifecycle.
# POST /api/auth/login -> session cookie -> GET /api/auth/me ->
# POST /api/auth/logout -> GET /api/auth/me with revoked cookie
# returns 401.
#
# Smoke verifies EFFECT (per the working agreement v1.3.20+):
# the password gate really validates, the session cookie really
# authorizes downstream requests, and logout really invalidates
# the cookie at the server (not just the client).
#
# Usage:
#   PANEL_BASE_URL=http://localhost:9180 \
#   ARGOS_USERNAME=<username> \
#   ARGOS_PASSWORD=<password> \
#     ./scripts/smoke/auth-flow.sh
#
# TOTP-enabled accounts: the smoke detects the requires_totp
# response and exits PASS-PARTIAL (password gate verified;
# the TOTP step needs interactive input). Use a non-TOTP test
# account if you want full coverage.
#
# This smoke creates and disposes its OWN session; it does NOT
# touch ARGOS_SESSION_TOKEN. Safe to run alongside other smokes.
#
# Exit codes:
#   0 = full lifecycle PASS (or PASS-PARTIAL on TOTP detect)
#   1 = an assertion diverged
#   2 = setup error (missing env, panel unreachable)

set -euo pipefail

PANEL_BASE_URL="${PANEL_BASE_URL:-http://localhost:9180}"
ARGOS_USERNAME="${ARGOS_USERNAME:-}"
ARGOS_PASSWORD="${ARGOS_PASSWORD:-}"

log()  { printf '[smoke/auth-flow] %s\n' "$*"; }
fail() { printf '[smoke/auth-flow] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() {
    printf '[smoke/auth-flow] SETUP: %s\n' "$*" >&2
    exit 2
}

[ -n "${ARGOS_USERNAME}" ] || setup_fail "ARGOS_USERNAME required"
[ -n "${ARGOS_PASSWORD}" ] || setup_fail "ARGOS_PASSWORD required"
command -v jq >/dev/null 2>&1 || setup_fail "jq required"

COOKIE_JAR=$(mktemp)
trap 'rm -f "${COOKIE_JAR}"' EXIT

# === phase 1: POST /api/auth/login ============================
log "[1/4] POST /api/auth/login (username=${ARGOS_USERNAME})"
LOGIN_RESP=$(curl -s -o /tmp/login.json -w '%{http_code}' \
    -c "${COOKIE_JAR}" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"${ARGOS_USERNAME}\",\"password\":\"${ARGOS_PASSWORD}\"}" \
    "${PANEL_BASE_URL}/api/auth/login")
[ "${LOGIN_RESP}" = "200" ] \
    || fail "login returned ${LOGIN_RESP}: $(cat /tmp/login.json)"

# Detect TOTP-pending shape: {"requires_totp":true,"challenge_id":"..."}.
if jq -e '.requires_totp == true' /tmp/login.json >/dev/null 2>&1; then
    log "  account has TOTP enabled; password gate verified"
    log "PASS-PARTIAL: login (password gate) succeeded; TOTP step skipped"
    exit 0
fi

USERNAME=$(jq -r '.username // empty' /tmp/login.json)
[ "${USERNAME}" = "${ARGOS_USERNAME}" ] \
    || fail "login response username mismatch: got '${USERNAME}'"
log "  logged in as ${USERNAME}"

# === phase 2: GET /api/auth/me with session cookie ============
log "[2/4] GET /api/auth/me with session cookie"
ME_RESP=$(curl -s -o /tmp/me.json -w '%{http_code}' \
    -b "${COOKIE_JAR}" \
    "${PANEL_BASE_URL}/api/auth/me")
[ "${ME_RESP}" = "200" ] \
    || fail "GET /me with session cookie returned ${ME_RESP}: $(cat /tmp/me.json)"
ME_USER=$(jq -r '.username // empty' /tmp/me.json)
[ "${ME_USER}" = "${ARGOS_USERNAME}" ] \
    || fail "/me returned wrong username: '${ME_USER}'"
log "  /me confirms session valid (${ME_USER})"

# === phase 3: POST /api/auth/logout ===========================
log "[3/4] POST /api/auth/logout"
LOGOUT_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -b "${COOKIE_JAR}" \
    -X POST "${PANEL_BASE_URL}/api/auth/logout")
[ "${LOGOUT_CODE}" = "200" ] || [ "${LOGOUT_CODE}" = "204" ] \
    || fail "logout returned ${LOGOUT_CODE}"
log "  logout returned ${LOGOUT_CODE}"

# === phase 4: cookie is revoked server-side ===================
log "[4/4] GET /api/auth/me after logout returns 401"
POST_LOGOUT_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -b "${COOKIE_JAR}" \
    "${PANEL_BASE_URL}/api/auth/me")
[ "${POST_LOGOUT_CODE}" = "401" ] \
    || fail "post-logout /me returned ${POST_LOGOUT_CODE} (expected 401 -- session not actually revoked server-side)"
log "  post-logout cookie correctly rejected with 401"

log "PASS: auth lifecycle (login -> me -> logout -> 401) verified"
