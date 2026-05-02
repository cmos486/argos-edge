#!/bin/bash
# scripts/smoke/capture-automation.sh
#
# v1.3.36 partial smoke for the capture automation. Runs without
# prod credentials -- the full end-to-end (login + 24 captures)
# requires a real productive panel + .env file and is operator-
# mediated only.
#
# What this smoke verifies:
#   1. scripts/capture/run.sh refuses to run without .env (clear
#      error, exit non-zero).
#   2. scripts/capture/.env is git-check-ignore'd.
#   3. scripts/capture/.env.example does NOT contain any
#      operator-specific data (just RFC-shaped placeholders).
#   4. safeClick blocklist works: synthetic test against the
#      lib/safe-page.js looksBlocked function.
#   5. The repo working tree stays clean across the smoke.
#
# Exit 0 PASS, 1 FAIL, 2 setup error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CAPTURE_DIR="${REPO_DIR}/scripts/capture"

log()  { printf '[smoke/capture] %s\n' "$*"; }
fail() { printf '[smoke/capture] FAIL: %s\n' "$*" >&2; exit 1; }

# Pre-flight
[ -d "${CAPTURE_DIR}" ]              || fail "missing ${CAPTURE_DIR}"
[ -x "${CAPTURE_DIR}/run.sh" ]       || fail "run.sh not executable"
[ -x "${CAPTURE_DIR}/run-demo.sh" ]  || fail "run-demo.sh not executable"
[ -f "${CAPTURE_DIR}/.env.example" ] || fail "missing .env.example"
[ -f "${CAPTURE_DIR}/package.json" ] || fail "missing package.json"
[ -f "${CAPTURE_DIR}/lib/safe-page.js" ] || fail "missing lib/safe-page.js"
command -v node >/dev/null || fail "node not on PATH"
command -v npm  >/dev/null || fail "npm not on PATH"

PRE_STATUS="$(cd "${REPO_DIR}" && git status --porcelain | sort)"

# --- 1. run.sh refuses without .env ---
log "phase 1: run.sh refuses to run without .env..."
ENV_BAK=""
if [ -f "${CAPTURE_DIR}/.env" ]; then
    ENV_BAK="${CAPTURE_DIR}/.env.smoke-bak"
    mv "${CAPTURE_DIR}/.env" "${ENV_BAK}"
fi
trap '[ -n "${ENV_BAK}" ] && [ -f "${ENV_BAK}" ] && mv "${ENV_BAK}" "${CAPTURE_DIR}/.env" || true' EXIT

# run.sh exits 1 on missing .env; with set -euo pipefail, piping
# directly to grep would short-circuit before grep runs. Capture
# the combined output (allow non-zero exit), then test the captured
# string in a separate step.
RUN_OUTPUT="$( "${CAPTURE_DIR}/run.sh" 2>&1 || true )"
if echo "${RUN_OUTPUT}" | grep -q "FAIL.*\.env"; then
    log "  PASS: run.sh refuses without .env (clear error)"
else
    log "  output was:"; echo "${RUN_OUTPUT}" | head -3 | sed 's/^/    /'
    fail "run.sh should have failed with .env-missing error"
fi

# --- 2. .env is gitignore'd ---
log "phase 2: .env is git check-ignore'd..."
echo "ARGOS_PROD_URL=https://example.com" > "${CAPTURE_DIR}/.env"
echo "ARGOS_PROD_USER=smoke-test" >> "${CAPTURE_DIR}/.env"
echo "ARGOS_PROD_PASS=smoke-test-pass" >> "${CAPTURE_DIR}/.env"

if ( cd "${REPO_DIR}" && git check-ignore "scripts/capture/.env" >/dev/null 2>&1 ); then
    log "  PASS: scripts/capture/.env is gitignore-recognized"
else
    fail ".env should be gitignored"
fi

if ( cd "${REPO_DIR}" && git status --porcelain | grep -q "scripts/capture/\.env$" ); then
    fail ".env appeared in git status (not gitignored)"
fi
log "  PASS: .env is invisible to git status"

rm -f "${CAPTURE_DIR}/.env"

# --- 3. .env.example has no operator data ---
log "phase 3: .env.example contains only RFC-shaped placeholders..."
if grep -E "(cmos486|kilian|192\.168\.|10\.[0-9]+\.)" "${CAPTURE_DIR}/.env.example" >/dev/null 2>&1; then
    fail ".env.example contains operator-specific data"
fi
if grep -E "argos\.example\.com|admin" "${CAPTURE_DIR}/.env.example" >/dev/null; then
    log "  PASS: .env.example has placeholder URL + username only"
else
    fail ".env.example unexpected content shape"
fi

# --- 4. safeClick blocklist works ---
log "phase 4: safeClick synthetic test (looksBlocked behaviour)..."
SAFE_TEST_DIR="$(mktemp -d)"
TRAP_EXTRA="rm -rf '${SAFE_TEST_DIR}'"

cat > "${SAFE_TEST_DIR}/test.js" <<'TESTEOF'
const { looksBlocked } = require('./safe-page.js');

const cases = [
    ['Save',                  true],
    ['Save changes',          true],
    ['Add',                   true],
    ['Add target',            true],
    ['Delete',                true],
    ['Submit',                true],
    ['Apply',                 true],
    ['Send test',             true],
    ['Refresh',               true],
    ['Whitelist',             true],
    ['Hosts',                 false],
    ['Activity',              false],
    ['Banned IPs',            false],
];

let ok = 0, bad = 0;
for (const [text, want] of cases) {
    const got = looksBlocked(text);
    if (got === want) {
        ok++;
    } else {
        bad++;
        console.log(`FAIL: looksBlocked(${JSON.stringify(text)}) = ${got}, want ${want}`);
    }
}
console.log(`safeClick blocklist: ${ok}/${cases.length} pass`);
process.exit(bad > 0 ? 1 : 0);
TESTEOF

cp "${CAPTURE_DIR}/lib/safe-page.js" "${SAFE_TEST_DIR}/safe-page.js"
if ( cd "${SAFE_TEST_DIR}" && node test.js ); then
    log "  PASS: safeClick blocklist behaviour matches expectations"
else
    rm -rf "${SAFE_TEST_DIR}"
    fail "safeClick blocklist test failed"
fi
rm -rf "${SAFE_TEST_DIR}"

# --- 5. Working tree clean across the smoke ---
log "phase 5: working tree unchanged by smoke..."
POST_STATUS="$(cd "${REPO_DIR}" && git status --porcelain | sort)"
if [ "${PRE_STATUS}" = "${POST_STATUS}" ]; then
    log "  PASS: git status identical pre/post smoke"
else
    log "  WARN: git status changed during smoke:"
    diff <(echo "${PRE_STATUS}") <(echo "${POST_STATUS}") | sed 's/^/    /' || true
    fail "smoke mutated the working tree (unexpected)"
fi

log "PASS: capture-automation partial smoke complete"
log "(full end-to-end smoke requires real prod credentials; run scripts/capture/run.sh manually)"
