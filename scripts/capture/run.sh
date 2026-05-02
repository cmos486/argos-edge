#!/usr/bin/env bash
# Capture session against a productive argos panel. Read-only:
# Playwright is locked down via lib/safe-page.js so any click whose
# target text matches a state-mutating verb (Save / Add / Delete /
# Apply / Confirm / Submit / Create / Run / Trigger / Restart /
# Reset / Send / Disable / Enable / Generate / Revoke / Ban /
# Whitelist / Purge / Refresh / Mark applied / Sign out) throws
# loudly.
#
# Output: /tmp/argos-captures-pending/*.png + .skip-list. The
# operator reviews each PNG, pixelates any sensitive operator data,
# and moves approved files to docs/screenshots/. THIS SCRIPT does
# NOT git add, git commit, git push, or otherwise touch the repo.
#
# State-dependent surfaces (true_detect_mode hosts, drift banner,
# selfblock banner, country expansion in progress, totp-setup) are
# auto-skipped against prod and logged to .skip-list. Capture them
# against the demo via run-demo.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
OUTPUT_DIR="${ARGOS_OUTPUT_DIR:-/tmp/argos-captures-pending}"

log()  { printf '[capture/run] %s\n' "$*"; }
fail() { printf '[capture/run] FAIL: %s\n' "$*" >&2; exit 1; }

# Pre-flight
if [ ! -f "${ENV_FILE}" ]; then
    cat >&2 <<EOF
[capture/run] FAIL: ${ENV_FILE} missing.

Copy the example and fill in your prod credentials (file is
gitignored; never commit it):

    cp ${SCRIPT_DIR}/.env.example ${ENV_FILE}
    \$EDITOR ${ENV_FILE}

Required fields: ARGOS_PROD_URL, ARGOS_PROD_USER, ARGOS_PROD_PASS.
EOF
    exit 1
fi

# shellcheck disable=SC1090
set -a; . "${ENV_FILE}"; set +a

[ -n "${ARGOS_PROD_URL:-}" ]  || fail ".env: ARGOS_PROD_URL is empty"
[ -n "${ARGOS_PROD_USER:-}" ] || fail ".env: ARGOS_PROD_USER is empty"
[ -n "${ARGOS_PROD_PASS:-}" ] || fail ".env: ARGOS_PROD_PASS is empty"

# Reset output dir each run so the operator's review starts from a
# clean slate.
log "preparing output dir ${OUTPUT_DIR}/ (fresh)..."
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

# Install Playwright if needed. node_modules/ is gitignored.
cd "${SCRIPT_DIR}"
if [ ! -d node_modules ]; then
    log "installing Playwright (first run only)..."
    npm ci
    log "downloading chromium browser binary..."
    npx playwright install chromium
fi

# Run the spec in prod mode.
log "running capture spec against ${ARGOS_PROD_URL} (read-only)..."
ARGOS_CAPTURE_MODE=prod \
ARGOS_OUTPUT_DIR="${OUTPUT_DIR}" \
    npx playwright test --reporter=list

# Summary: list captured + skip-list contents.
echo ""
echo "=========================================="
echo "  Captures in ${OUTPUT_DIR}/"
echo "=========================================="
( cd "${OUTPUT_DIR}" && ls -1 *.png 2>/dev/null || echo "(no captures landed)" ) | sed 's/^/  /'

echo ""
echo "  Skip list (.skip-list):"
if [ -s "${OUTPUT_DIR}/.skip-list" ]; then
    sed 's/^/    /' "${OUTPUT_DIR}/.skip-list"
else
    echo "    (none)"
fi

echo ""
cat <<EOF
  Operator next steps:
    1. Review each PNG visually.
    2. Pixelate any sensitive operator data (real domains, LAN IPs,
       personal email, real bot tokens that may have leaked into a
       tooltip).
    3. Move approved PNGs from ${OUTPUT_DIR}/ to docs/screenshots/.
    4. Commit only the approved files with scope docs(screenshots).

  This script never moves PNGs into the repo and never commits.
EOF
