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

# Single combined trap covering all cleanups (consolidated to avoid
# clobbering: every `trap '...' EXIT` REPLACES the previous one).
# Stash an operator-supplied .env outside the repo so the bak file
# can never show up in git status mid-smoke.
SMOKE_TMP="$(mktemp -d -t argos-smoke-XXXXXX)"
SAFE_TEST_DIR=""
ENV_BAK_PATH="${SMOKE_TMP}/operator-env"
trap '
    [ -n "${SAFE_TEST_DIR}" ] && rm -rf "${SAFE_TEST_DIR}"
    if [ -f "${ENV_BAK_PATH}" ]; then
        mv "${ENV_BAK_PATH}" "${CAPTURE_DIR}/.env"
    fi
    rm -rf "${SMOKE_TMP}"
' EXIT INT TERM

# --- 1. run.sh refuses without .env ---
log "phase 1: run.sh refuses to run without .env..."
if [ -f "${CAPTURE_DIR}/.env" ]; then
    mv "${CAPTURE_DIR}/.env" "${ENV_BAK_PATH}"
fi

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
    fail "safeClick blocklist test failed"
fi
# (cleanup handled by the consolidated trap)

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

# --- 6. v1.3.36.1: storageState wiring is in place ---
log "phase 6: storageState wiring (v1.3.36.1 auth-persistence fix)..."

if [ ! -f "${CAPTURE_DIR}/auth.setup.js" ]; then
    fail "auth.setup.js missing -- v1.3.36.1 setup project not wired"
fi
log "  PASS: auth.setup.js present"

if ! grep -q "storageState" "${CAPTURE_DIR}/auth.setup.js"; then
    fail "auth.setup.js doesn't reference storageState"
fi
log "  PASS: auth.setup.js calls context.storageState"

if ! grep -q "storageState" "${CAPTURE_DIR}/playwright.config.js"; then
    fail "playwright.config.js doesn't wire storageState into the captures project"
fi
log "  PASS: playwright.config.js declares use.storageState"

if ! grep -q "dependencies.*setup" "${CAPTURE_DIR}/playwright.config.js"; then
    fail "playwright.config.js captures project doesn't depend on setup project"
fi
log "  PASS: captures project depends on setup project"

# Trap cleanup in run.sh + run-demo.sh
for sh in run.sh run-demo.sh; do
    if ! grep -q "trap.*AUTH_STATE.*EXIT" "${CAPTURE_DIR}/${sh}"; then
        fail "${sh} missing trap to clean up AUTH_STATE on exit"
    fi
done
log "  PASS: run.sh + run-demo.sh trap-clean the auth state file"

# --- 7. v1.3.36.1: banner output uses real JS, not bash command sub ---
log "phase 7: banner output uses fs.readFileSync (no shell command sub)..."

# Match only active code: console.log lines containing $(. Comment
# blocks documenting the v1.3.36 bug history are allowed.
if grep -E '^[^/]*console\.log\([^)]*\$\(' "${CAPTURE_DIR}/capture.spec.js" | grep -qv '^\s*//'; then
    log "  offending line:"; grep -nE '^[^/]*console\.log\([^)]*\$\(' "${CAPTURE_DIR}/capture.spec.js" | sed 's/^/    /'
    fail "capture.spec.js has live console.log with literal \$(...) bash command-substitution syntax"
fi
log "  PASS: no live console.log uses bash command-substitution"

if ! grep -q "fs.readFileSync.*SKIP_LIST_PATH" "${CAPTURE_DIR}/capture.spec.js"; then
    fail "capture.spec.js doesn't read skip-list with fs.readFileSync"
fi
log "  PASS: capture.spec.js uses fs.readFileSync for skip count"

# --- 8. v1.3.36.1: viewport bumped + shotFullScroll helper present ---
log "phase 8: viewport 1440x1080 + shotFullScroll helper..."

if ! grep -q "width: 1440, height: 1080" "${CAPTURE_DIR}/playwright.config.js"; then
    fail "playwright.config.js viewport not bumped to 1440x1080"
fi
log "  PASS: viewport is 1440x1080"

if ! grep -q "function shotFullScroll" "${CAPTURE_DIR}/capture.spec.js"; then
    fail "capture.spec.js missing shotFullScroll() helper"
fi
log "  PASS: shotFullScroll() helper present"

# Count surfaces using each helper -- sanity-check the split.
N_FULLSCROLL="$(grep -c 'shotFullScroll' "${CAPTURE_DIR}/capture.spec.js")"
N_FULL="$(grep -c 'shotFull(' "${CAPTURE_DIR}/capture.spec.js")"
log "  shotFullScroll calls: ${N_FULLSCROLL}; shotFull calls: ${N_FULL}"

# --- 9. v1.3.36.2: waitForSettled helper structure + universal use ---
log "phase 9: waitForSettled helper (timing fix)..."

if ! grep -q "async function waitForSettled" "${CAPTURE_DIR}/capture.spec.js"; then
    fail "capture.spec.js missing waitForSettled() helper"
fi
log "  PASS: waitForSettled() helper defined"

# Helper must use networkidle (the dynamic primary path).
if ! grep -A 5 "async function waitForSettled" "${CAPTURE_DIR}/capture.spec.js" \
   | grep -q "waitForLoadState.*networkidle"; then
    fail "waitForSettled() doesn't call waitForLoadState('networkidle')"
fi
log "  PASS: waitForSettled() uses networkidle as primary"

# Helper must have a fallback wait branch (try/catch for the
# networkidle timeout).
if ! grep -A 10 "async function waitForSettled" "${CAPTURE_DIR}/capture.spec.js" \
   | grep -q "waitForTimeout.*fallback"; then
    fail "waitForSettled() doesn't fall back to waitForTimeout(fallback) on timeout"
fi
log "  PASS: waitForSettled() has fallback timeout branch"

# Sanity: every test() that does page.goto should have a settle
# step (waitForSettled OR a waitForSelector specific selector
# right after). We just count waitForSettled invocations vs goto
# count and warn if the gap is suspicious.
N_GOTO="$(grep -c 'page\.goto(' "${CAPTURE_DIR}/capture.spec.js")"
N_SETTLED="$(grep -c 'waitForSettled' "${CAPTURE_DIR}/capture.spec.js")"
log "  page.goto calls: ${N_GOTO}; waitForSettled calls: ${N_SETTLED}"
if [ "${N_SETTLED}" -lt 20 ]; then
    fail "waitForSettled invocation count ${N_SETTLED} suspiciously low; tests may still fire screenshots immediately after goto"
fi
log "  PASS: waitForSettled used pervasively (>= 20 calls)"

# Old inconsistent pattern should NOT still be in the file
# (waitForLoadState networkidle 5_000 with .catch was the
# pre-v1.3.36.2 hack-fix; replaced uniformly with waitForSettled).
if grep -E 'waitForLoadState.*networkidle.*5_000.*catch' "${CAPTURE_DIR}/capture.spec.js" >/dev/null; then
    fail "capture.spec.js still has the pre-v1.3.36.2 'waitForLoadState networkidle 5_000 .catch' inline pattern"
fi
log "  PASS: no leftover pre-v1.3.36.2 inline waits"

# --- 10. v1.3.36.3: openModal modalSelector + correct TG button ---
log "phase 10: openModal modal-visibility wait + target-group selector..."

# 10a: openModal helper now accepts a modalSelector 4th argument.
if ! grep -A 30 "async function openModal" "${CAPTURE_DIR}/lib/safe-page.js" \
   | grep -q "modalSelector"; then
    fail "openModal() doesn't accept modalSelector argument"
fi
log "  PASS: openModal() accepts modalSelector"

# 10b: openModal body has the post-click waitForSelector + animation
# settle pattern.
if ! grep -A 30 "async function openModal" "${CAPTURE_DIR}/lib/safe-page.js" \
   | grep -q "waitForSelector.*modalSelector"; then
    fail "openModal() doesn't waitForSelector(modalSelector) post-click"
fi
log "  PASS: openModal() waits for modalSelector visibility post-click"

if ! grep -A 30 "async function openModal" "${CAPTURE_DIR}/lib/safe-page.js" \
   | grep -q "waitForTimeout"; then
    fail "openModal() missing animation-settle waitForTimeout"
fi
log "  PASS: openModal() applies animation-settle delay"

# 10c: capture.spec.js modal-open call sites pass the .fixed.inset-0.z-40
# overlay selector (the panel's <Modal> overlay class). Five sites:
# host-form, host-form-dns-provider-dropdown (first call), host-form-
# true-detect, target-group-form, totp-setup. Count occurrences as
# a sanity-check.
N_OVERLAY="$(grep -c "fixed.inset-0.z-40" "${CAPTURE_DIR}/capture.spec.js")"
log "  capture.spec.js .fixed.inset-0.z-40 references: ${N_OVERLAY}"
if [ "${N_OVERLAY}" -lt 5 ]; then
    fail "expected >= 5 modal-open call sites passing the overlay selector, got ${N_OVERLAY}"
fi
log "  PASS: >= 5 modal-open call sites wired to wait for overlay"

# 10d: target-group-form selector now matches the real button text
# "Add target group" (per TargetGroups.tsx:66). v1.3.36.x had
# "Create" / "New target group" / [data-testid="create-tg"] -- none
# matched.
if ! grep -q 'has-text("Add target group")' "${CAPTURE_DIR}/capture.spec.js"; then
    fail "target-group-form selector doesn't include 'Add target group' text"
fi
log "  PASS: target-group-form uses 'Add target group' selector"

# Also check that the OLD selector strings are gone from ACTIVE
# code (comments documenting the bug history are allowed).
if grep -nE 'has-text\("New target group"\)|"create-tg"' "${CAPTURE_DIR}/capture.spec.js" \
   | grep -v '^\s*[0-9]*:\s*//' >/dev/null; then
    log "  output (active code only):"
    grep -nE 'has-text\("New target group"\)|"create-tg"' "${CAPTURE_DIR}/capture.spec.js" \
        | grep -v '^\s*[0-9]*:\s*//' | sed 's/^/    /'
    fail "old TG selector strings still present in active code; clean up the fallbacks"
fi
log "  PASS: old TG selector fallbacks removed from active code"

# --- 11. v1.3.36.4: host-row edit-button trigger fix ---
log "phase 11: host-row triggers click button[aria-label=\"edit\"]..."

# 11a: capture.spec.js modal-open call sites for hosts must scope
# the click to the IconButton (aria-label="edit"), not the row.
# Three call sites: test 5 (host-form), test 6 (host-form-dns-
# provider-dropdown first call), test 8 (host-form-true-detect).
# Count active-code occurrences of the new selector pattern.
N_EDIT_SEL="$(grep -cE "tr[^']*button\[aria-label=\"edit\"\]" "${CAPTURE_DIR}/capture.spec.js")"
log "  active-code 'tr ... button[aria-label=\"edit\"]' occurrences: ${N_EDIT_SEL}"
if [ "${N_EDIT_SEL}" -lt 3 ]; then
    fail "expected >= 3 call sites scoping to button[aria-label=\"edit\"], got ${N_EDIT_SEL}"
fi
log "  PASS: 3 call sites click the edit-trigger button (not the row)"

# 11b: synthetic verify -- the actual frontend IconButton renders
# with aria-label set from the prop. Inspect Hosts.tsx to confirm.
HOSTS_TSX="${REPO_DIR}/frontend/src/pages/Hosts.tsx"
if [ ! -f "${HOSTS_TSX}" ]; then
    log "  SKIP: ${HOSTS_TSX} missing (Go-only checkout?)"
elif ! grep -q 'aria-label={label}' "${HOSTS_TSX}"; then
    fail "Hosts.tsx IconButton no longer renders aria-label={label} -- selector will break"
elif ! grep -q '<IconButton label="edit"' "${HOSTS_TSX}"; then
    fail "Hosts.tsx no longer has <IconButton label=\"edit\"> -- selector will break"
else
    log "  PASS: Hosts.tsx IconButton + label=\"edit\" present (aria-label resolves to \"edit\")"
fi

# --- 12. v1.3.36.5: tab-click false-positive fix (safeClickTab) ---
log "phase 12: safeClickTab helper + tab-click migrations..."

if ! grep -q "async function safeClickTab" "${CAPTURE_DIR}/lib/safe-page.js"; then
    fail "safeClickTab() helper missing from lib/safe-page.js"
fi
log "  PASS: safeClickTab() helper defined"

# Helper must require a reason (audit log).
if ! grep -A 8 "async function safeClickTab" "${CAPTURE_DIR}/lib/safe-page.js" \
   | grep -q "requires a reason"; then
    fail "safeClickTab() doesn't enforce required reason argument"
fi
log "  PASS: safeClickTab() requires reason argument"

# Helper must be exported.
if ! grep -E '^module\.exports' "${CAPTURE_DIR}/lib/safe-page.js" \
   | grep -q "safeClickTab"; then
    fail "safeClickTab() not exported from lib/safe-page.js"
fi
log "  PASS: safeClickTab() exported"

# capture.spec.js imports the helper.
if ! grep -q "safeClickTab" "${CAPTURE_DIR}/capture.spec.js"; then
    fail "capture.spec.js doesn't import safeClickTab"
fi
log "  PASS: capture.spec.js imports safeClickTab"

# Six tab-click call sites migrated to safeClickTab.
N_TAB="$(grep -c "safeClickTab(page" "${CAPTURE_DIR}/capture.spec.js")"
log "  capture.spec.js safeClickTab call sites: ${N_TAB}"
if [ "${N_TAB}" -lt 6 ]; then
    fail "expected >= 6 safeClickTab call sites, got ${N_TAB}"
fi
log "  PASS: >= 6 tab-click call sites use safeClickTab"

# The Whitelist tab specifically must be wired through safeClickTab
# (this is the regression that triggered v1.3.36.5).
if ! grep -q 'safeClickTab.*"Whitelist"' "${CAPTURE_DIR}/capture.spec.js"; then
    fail "Whitelist tab still uses safeClick (would re-trigger the v1.3.36.4 false positive)"
fi
log "  PASS: Whitelist tab specifically wired through safeClickTab"

# --- 13. v1.3.36.5: DNS-01 selector fix ---
log "phase 13: DNS-01 selector fix (label:has-text vs broken input[value=dns])..."

# Active code must use label:has-text("DNS-01"), not the broken
# input[value="dns"] selector (which matched zero elements because
# ChallengeRadio doesn't set the value attribute).
if ! grep -q 'label:has-text("DNS-01")' "${CAPTURE_DIR}/capture.spec.js"; then
    fail "capture.spec.js missing 'label:has-text(\"DNS-01\")' selector"
fi
log "  PASS: DNS-01 click uses 'label:has-text(\"DNS-01\")'"

# The OLD broken selector should be gone from active code (the
# v1.3.36.5 release-notes comment in test 6 documents it as the
# failure mode -- comment lines allowed).
if grep -nE 'input\[type="radio"\]\[value="dns"\]' "${CAPTURE_DIR}/capture.spec.js" \
   | grep -v '^\s*[0-9]*:\s*//' >/dev/null; then
    log "  offending line(s):"
    grep -nE 'input\[type="radio"\]\[value="dns"\]' "${CAPTURE_DIR}/capture.spec.js" \
        | grep -v '^\s*[0-9]*:\s*//' | sed 's/^/    /'
    fail "old broken input[value=\"dns\"] selector still in active code"
fi
log "  PASS: old broken input[value=\"dns\"] selector removed from active code"

# Synthetic verify against the frontend: ChallengeRadio must still
# render the <label> wrapping an <input>, with the label text in
# its first <span>. If the component is refactored, the selector
# breaks.
HOSTS_TSX="${REPO_DIR}/frontend/src/pages/Hosts.tsx"
if [ ! -f "${HOSTS_TSX}" ]; then
    log "  SKIP: ${HOSTS_TSX} missing (Go-only checkout?)"
elif ! grep -A 30 "function ChallengeRadio" "${HOSTS_TSX}" \
       | grep -q '<label'; then
    fail "ChallengeRadio no longer wraps the input in a <label> -- selector will break"
elif ! grep -A 30 "function ChallengeRadio" "${HOSTS_TSX}" \
       | grep -q '{label}'; then
    fail "ChallengeRadio no longer renders the {label} prop as visible text -- :has-text(\"DNS-01\") will break"
else
    log "  PASS: Hosts.tsx ChallengeRadio still renders <label> with {label} prop visible"
fi

# --- 14. v1.3.36.7: threats-decisions selector (h1 anchor only) ---
log "phase 14: threats-decisions selector fix..."

# Active code MUST use h1:has-text("Threats") -- the only proven-
# reliable anchor in the operator's prod. v1.3.36.6's additional
# h2:has-text("Active decisions") wait timed out despite being
# unconditional in Threats.tsx source; cause unconfirmed but
# Option B drops the h2 dependency entirely.
if ! grep -q 'h1:has-text("Threats")' "${CAPTURE_DIR}/capture.spec.js"; then
    fail "test 20 doesn't use h1:has-text(\"Threats\") anchor"
fi
log "  PASS: threats-decisions waits for h1:Threats anchor"

# Old broken 'table, [role="tabpanel"]' must be gone from active
# code (comments documenting the failure mode are allowed).
if grep -nE 'table, \[role="tabpanel"\]' "${CAPTURE_DIR}/capture.spec.js" \
   | grep -v '^\s*[0-9]*:\s*//' >/dev/null; then
    log "  offending line(s):"
    grep -nE 'table, \[role="tabpanel"\]' "${CAPTURE_DIR}/capture.spec.js" \
        | grep -v '^\s*[0-9]*:\s*//' | sed 's/^/    /'
    fail "old broken 'table, [role=\"tabpanel\"]' selector still in active code"
fi
log "  PASS: old broken table/tabpanel selector removed from active code"

# v1.3.36.6's h2 anchor must also be gone from active code (same
# allowance for comment lines documenting the failure mode).
if grep -nE 'waitForSelector.*h2:has-text\("Active decisions"\)' "${CAPTURE_DIR}/capture.spec.js" \
   | grep -v '^\s*[0-9]*:\s*//' >/dev/null; then
    log "  offending line(s):"
    grep -nE 'waitForSelector.*h2:has-text\("Active decisions"\)' "${CAPTURE_DIR}/capture.spec.js" \
        | grep -v '^\s*[0-9]*:\s*//' | sed 's/^/    /'
    fail "v1.3.36.6 h2:Active decisions wait still in active code (Option B drops it)"
fi
log "  PASS: v1.3.36.6 h2 anchor removed from active code"

# Synthetic verify -- Threats.tsx still has the <h1>...Threats
# heading. If the page is renamed, phase 14 fails loudly.
THREATS_TSX="${REPO_DIR}/frontend/src/pages/Threats.tsx"
if [ ! -f "${THREATS_TSX}" ]; then
    log "  SKIP: ${THREATS_TSX} missing (Go-only checkout?)"
elif ! grep -q '<h1' "${THREATS_TSX}"; then
    fail "Threats.tsx no longer has <h1> element"
elif ! grep -q 'Threats' "${THREATS_TSX}"; then
    fail "Threats.tsx no longer mentions 'Threats' -- page may have been renamed"
else
    log "  PASS: Threats.tsx has <h1> and 'Threats' text"
fi

log "PASS: capture-automation partial smoke complete"
log "(full end-to-end smoke requires real prod credentials; run scripts/capture/run.sh manually)"
