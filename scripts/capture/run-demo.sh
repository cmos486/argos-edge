#!/usr/bin/env bash
# Capture session against the v1.3.35.4+ demo stack. Used for the
# state-dependent surfaces that run.sh skips against prod:
#
#   drift-indicators.png        (demo seed sets drift_detected:true)
#   country-bans-progress.png   (demo seed has 8 country bans; static
#                                 capture of the table state)
#   host-form-true-detect.png   (demo seed has 3 hosts with
#                                 true_detect_mode=true)
#   hosts-detect-badge.png      (same)
#   target-group-two-targets.png (demo seed; check before run)
#   selfblock-banner.png        (operator runs `argos demo
#                                 seed-self-block --yes` BEFORE this
#                                 script; banner visible during run)
#   totp-setup.png              (fresh demo, 2FA not yet enabled)
#
# Same read-only contract as run.sh -- the safeClick blocklist is
# enforced even against the demo so a buggy spec can't accidentally
# wipe demo-seeded state.
#
# Output: /tmp/argos-captures-pending/ (same path as run.sh, but
# different filenames; running run.sh after run-demo.sh OVERWRITES
# the prod surfaces with demo screenshots in the operator's pending
# tray. If you want both kept, copy /tmp/argos-captures-pending/
# elsewhere before running the second script.)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env.demo"
OUTPUT_DIR="${ARGOS_OUTPUT_DIR:-/tmp/argos-captures-pending}"
AUTH_STATE="${ARGOS_AUTH_STATE:-/tmp/argos-auth-state.json}"

trap 'rm -f "${AUTH_STATE}"' EXIT INT TERM

log()  { printf '[capture/run-demo] %s\n' "$*"; }
fail() { printf '[capture/run-demo] FAIL: %s\n' "$*" >&2; exit 1; }

# Pre-flight: .env.demo separate from .env (so the prod creds and
# demo creds don't get confused at the shell layer).
if [ ! -f "${ENV_FILE}" ]; then
    log "no ${ENV_FILE} found; using built-in demo defaults"
    log "(operator can override by creating ${ENV_FILE} with the same env vars)"
fi

export ARGOS_PROD_URL="${ARGOS_PROD_URL:-http://localhost:9181}"
export ARGOS_PROD_USER="${ARGOS_PROD_USER:-demo}"
export ARGOS_PROD_PASS="${ARGOS_PROD_PASS:-demo1234}"

if [ -f "${ENV_FILE}" ]; then
    # shellcheck disable=SC1090
    set -a; . "${ENV_FILE}"; set +a
fi

# Sanity: the URL should NOT look like a productive panel.
case "${ARGOS_PROD_URL}" in
    http://localhost:*|http://127.*|http://*.lan|http://*.home|http://argos-demo*)
        ;;
    *)
        cat >&2 <<EOF
[capture/run-demo] FAIL: ARGOS_PROD_URL='${ARGOS_PROD_URL}' does not look
like a demo URL. run-demo.sh is for the demo stack
(http://localhost:9181 by default). To capture against prod, use
run.sh instead.
EOF
        exit 1
        ;;
esac

log "preparing output dir ${OUTPUT_DIR}/ (fresh)..."
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

cd "${SCRIPT_DIR}"
if [ ! -d node_modules ]; then
    log "installing Playwright (first run only)..."
    npm ci
    log "downloading chromium browser binary..."
    npx playwright install chromium
fi

log "running capture spec against ${ARGOS_PROD_URL} in DEMO mode..."
ARGOS_CAPTURE_MODE=demo \
ARGOS_OUTPUT_DIR="${OUTPUT_DIR}" \
ARGOS_AUTH_STATE="${AUTH_STATE}" \
    npx playwright test --reporter=list

echo ""
echo "=========================================="
echo "  Demo captures in ${OUTPUT_DIR}/"
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
  Demo-mode-specific captures landed (state pre-seeded):
    drift-indicators.png         (drift_state.drift_detected=true seeded)
    country-bans-progress.png    (8 country bans visible in the table)
    host-form-true-detect.png    (admin/grafana/vault have the flag)
    hosts-detect-badge.png       (DETECT pill visible on those rows)
    target-group-two-targets.png (any TG with >=2 targets in seed)
    totp-setup.png               (fresh demo; 2FA not yet enabled)
    selfblock-banner.png         (only if you ran 'argos demo
                                  seed-self-block --yes' first)

  Same operator workflow as run.sh: review, sanitize if needed
  (demo data is RFC5737 + example.* but a stray real-world tooltip
  can still slip in), move approved to docs/screenshots/.
EOF
