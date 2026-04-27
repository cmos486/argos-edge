#!/bin/bash
# scripts/smoke/deploy-rebuild.sh
#
# v1.3.34.3 EFFECT smoke for the deploy-prod rebuild flow.
# Verifies that the new make build-prod-image + deploy-prod chain
# actually rebuilds the panel binary, retags the image, updates the
# override.yml image: line, and brings up a fresh container whose
# /argos --version + /api/system/version both report the new value.
#
# This is the smoke that closes the eleventh strike: pre-v1.3.34.3,
# `make deploy-prod` was a silent no-op rebuild because the override
# pinned `image: argos-prod-argos:v1.3.33` + had `build: !reset`.
# Two prior fix releases (v1.3.34.1, v1.3.34.2) shipped under that
# hidden gap.
#
# What it does:
#   1. Captures the current argosVersion from main.go.
#   2. Patches main.go with a sentinel version (current + ".smoke").
#   3. Runs make deploy-prod.
#   4. Asserts:
#        - docker images shows argos-prod-argos:<sentinel>
#        - container is running with the new image
#        - /argos --help reports the sentinel
#        - /api/system/version reports the sentinel (if session token)
#        - override.yml image: line was rewritten to the sentinel
#   5. Restores main.go.
#   6. Re-runs make deploy-prod to leave the stack on the original tag.
#
# Destructive: mutates the running prod stack. Refuses to run without
# --yes so a copy-paste in a wrong terminal doesn't accidentally
# trigger a double-rebuild.
#
# Exit 0 on PASS, 1 on FAIL, 2 on setup error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MAIN_GO="${REPO_DIR}/backend/cmd/argos/main.go"
ARGOS_PROD_DIR="${ARGOS_PROD_DIR:-${HOME}/argos-prod}"
OVERRIDE="${ARGOS_PROD_DIR}/docker-compose.override.yml"

log()  { printf '[smoke/deploy-rebuild] %s\n' "$*"; }
fail() { printf '[smoke/deploy-rebuild] FAIL: %s\n' "$*" >&2; exit 1; }

YES=0
for a in "$@"; do
    case "$a" in
        --yes|-y) YES=1 ;;
        -h|--help)
            sed -n '2,30p' "$0"
            exit 0
            ;;
    esac
done
if [ "${YES}" -ne 1 ]; then
    log "destructive smoke; pass --yes to confirm"
    log "this rebuilds the argos-prod-panel container twice (sentinel"
    log "tag + restore tag) and is meant to be run on a host with"
    log "a working argos-prod stack. Aborting."
    exit 2
fi

# Pre-flight checks
[ -f "${MAIN_GO}" ] || { echo "missing ${MAIN_GO}"; exit 2; }
[ -d "${ARGOS_PROD_DIR}" ] || { echo "missing ${ARGOS_PROD_DIR}"; exit 2; }
[ -f "${OVERRIDE}" ] || { echo "missing ${OVERRIDE}"; exit 2; }
docker compose ps >/dev/null 2>&1 || { echo "docker compose unavailable"; exit 2; }

# Capture original state
ORIG_VER="$(grep -oE 'argosVersion = "[^"]+"' "${MAIN_GO}" | head -1 | cut -d'"' -f2)"
[ -n "${ORIG_VER}" ] || fail "could not parse argosVersion from main.go"
SENTINEL="${ORIG_VER}-smoke"
log "original version: v${ORIG_VER}"
log "sentinel version: v${SENTINEL}"

ORIG_OVERRIDE_IMAGE="$(grep -oE 'image: argos-prod-argos:[^ ]+' "${OVERRIDE}" | head -1)"
log "original override image line: ${ORIG_OVERRIDE_IMAGE}"

# Trap for cleanup if anything fails mid-test
restore() {
    local rc=$?
    log "restoring main.go to v${ORIG_VER}..."
    sed -i -E "s|(var argosVersion = )\"[^\"]+\"|\1\"${ORIG_VER}\"|" "${MAIN_GO}"
    if [ ${rc} -ne 0 ]; then
        log "restore-only path (no redeploy); operator should run make deploy-prod"
    fi
    return ${rc}
}
trap restore EXIT

# Step 1: patch main.go to the sentinel
log "phase 1: patching main.go..."
sed -i -E "s|(var argosVersion = )\"[^\"]+\"|\1\"${SENTINEL}\"|" "${MAIN_GO}"
PATCHED_VER="$(grep -oE 'argosVersion = "[^"]+"' "${MAIN_GO}" | head -1 | cut -d'"' -f2)"
[ "${PATCHED_VER}" = "${SENTINEL}" ] || fail "patch did not stick: got ${PATCHED_VER}"

# Step 2: run deploy-prod
log "phase 2: make deploy-prod (expect rebuild + retag)..."
( cd "${REPO_DIR}" && make deploy-prod ) || fail "deploy-prod failed"

# Step 3: assertions
log "phase 3: verifying..."
sleep 6 # health re-stabilises after force-recreate

# 3a. image exists
if ! docker images "argos-prod-argos:${SENTINEL}" --format '{{.ID}}' | grep -q .; then
    fail "image argos-prod-argos:${SENTINEL} not found in local registry"
fi
log "  PASS: argos-prod-argos:${SENTINEL} image present"

# 3b. override file points at the sentinel
if ! grep -q "image: argos-prod-argos:${SENTINEL}" "${OVERRIDE}"; then
    fail "override.yml image: line not bumped to ${SENTINEL}"
fi
log "  PASS: override.yml image: rewritten"

# 3c. running container uses the new image
RUNNING_IMG="$(docker inspect argos-prod-panel --format '{{.Config.Image}}' 2>/dev/null || true)"
if [ "${RUNNING_IMG}" != "argos-prod-argos:${SENTINEL}" ]; then
    fail "running container image=${RUNNING_IMG}, expected argos-prod-argos:${SENTINEL}"
fi
log "  PASS: running container uses ${RUNNING_IMG}"

# 3d. binary --version
BIN_VER="$(docker exec argos-prod-panel /argos --help 2>/dev/null | head -1 | awk '{print $2}')"
if [ "${BIN_VER}" != "${SENTINEL}" ]; then
    fail "/argos --help reports v${BIN_VER}, expected v${SENTINEL}"
fi
log "  PASS: /argos --help reports v${BIN_VER}"

# 3e. /api/system/version (only if session token provided)
if [ -n "${ARGOS_SESSION_TOKEN:-}" ]; then
    API_VER="$(curl -sf -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        http://localhost:9180/api/system/version 2>/dev/null \
        | grep -oE '"version":"[^"]+"' | cut -d'"' -f4)"
    if [ "${API_VER}" != "${SENTINEL}" ]; then
        fail "/api/system/version reports v${API_VER}, expected v${SENTINEL}"
    fi
    log "  PASS: /api/system/version reports v${API_VER}"
else
    log "  SKIP: ARGOS_SESSION_TOKEN unset; API surface not asserted"
fi

# Step 4: restore + redeploy
log "phase 4: restoring main.go to v${ORIG_VER} + redeploying..."
trap - EXIT
sed -i -E "s|(var argosVersion = )\"[^\"]+\"|\1\"${ORIG_VER}\"|" "${MAIN_GO}"

( cd "${REPO_DIR}" && make deploy-prod ) || fail "restore-deploy failed"
sleep 6

# Confirm the restore landed
RESTORE_VER="$(docker exec argos-prod-panel /argos --help 2>/dev/null | head -1 | awk '{print $2}')"
if [ "${RESTORE_VER}" != "${ORIG_VER}" ]; then
    fail "post-restore binary reports v${RESTORE_VER}, expected v${ORIG_VER}"
fi
log "  PASS: stack restored to v${RESTORE_VER}"

log "PASS: deploy-rebuild EFFECT smoke complete"
exit 0
