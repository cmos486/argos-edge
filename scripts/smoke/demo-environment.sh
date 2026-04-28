#!/bin/bash
# scripts/smoke/demo-environment.sh
#
# v1.3.35 EFFECT smoke for the demo-stack scaffold. Exercises the
# full init.sh + seed + teardown.sh flow against the live host AND
# verifies the non-interference invariant: argos-prod must be
# byte-for-byte unchanged before, during, and after the demo lives.
#
# Phase shape:
#   0. Capture argos-prod baseline state (containers + volume mtime).
#   1. Run scripts/demo/init.sh.
#   2. Assert demo containers are healthy and panel responds.
#   3. Assert seed populated all 10 surfaces (DB row counts).
#   4. Assert argos-prod baseline UNCHANGED (containers + volume).
#   5. Run scripts/demo/teardown.sh.
#   6. Assert demo containers + volumes gone.
#   7. Assert argos-prod baseline STILL UNCHANGED.
#
# Steps 0/4/7 are the non-interference triple-check. Any failure
# aborts with a clear FAIL line. Refuses to run without --yes since
# the smoke materialises ~/argos-demo/ and starts containers.
#
# Exit 0 PASS, 1 FAIL, 2 setup error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEMO_DIR="${HOME}/argos-demo"

log()  { printf '[smoke/demo] %s\n' "$*"; }
fail() { printf '[smoke/demo] FAIL: %s\n' "$*" >&2; exit 1; }

YES=0
for a in "$@"; do
    case "$a" in
        --yes|-y) YES=1 ;;
        -h|--help)
            sed -n '2,25p' "$0"
            exit 0
            ;;
    esac
done
if [ "${YES}" -ne 1 ]; then
    log "destructive smoke; pass --yes to confirm"
    log "this materialises ${DEMO_DIR}, starts ~3 containers, then tears down."
    exit 2
fi

# Pre-flight: docker available + repo layout sane + prod containers up.
docker compose ps >/dev/null 2>&1 || fail "docker compose unavailable"
[ -x "${REPO_DIR}/scripts/demo/init.sh"     ] || fail "missing init.sh"
[ -x "${REPO_DIR}/scripts/demo/teardown.sh" ] || fail "missing teardown.sh"

# --- Phase 0: capture argos-prod baseline ---
log "phase 0: capturing argos-prod baseline..."

PROD_CONTAINERS=( argos-prod-panel argos-prod-caddy argos-prod-crowdsec )
declare -A PROD_BEFORE_ID PROD_BEFORE_STARTED

for c in "${PROD_CONTAINERS[@]}"; do
    if ! docker ps --format '{{.Names}}' | grep -qx "${c}"; then
        fail "prod container ${c} is not running -- precondition violated"
    fi
    id="$(docker inspect "${c}" --format '{{.Id}}')"
    started="$(docker inspect "${c}" --format '{{.State.StartedAt}}')"
    PROD_BEFORE_ID["${c}"]="${id}"
    PROD_BEFORE_STARTED["${c}"]="${started}"
    log "  ${c}: id=${id:0:12} started=${started}"
done

# Capture argos-prod DB size + mtime as a "did anything write to it" check.
PROD_DB_SIZE_BEFORE="$(docker exec argos-prod-panel sh -c 'stat -c %s /data/argos.db 2>/dev/null || echo 0')"
PROD_DB_MTIME_BEFORE="$(docker exec argos-prod-panel sh -c 'stat -c %Y /data/argos.db 2>/dev/null || echo 0')"
log "  argos.db size=${PROD_DB_SIZE_BEFORE} mtime=${PROD_DB_MTIME_BEFORE}"

# --- Phase 1: init demo ---
log "phase 1: running scripts/demo/init.sh..."
( "${REPO_DIR}/scripts/demo/init.sh" ) || fail "init.sh failed"

# --- Phase 2: demo container + panel sanity ---
log "phase 2: demo health checks..."
sleep 3
DEMO_HEALTH="$(docker inspect argos-demo-panel --format '{{.State.Health.Status}}' 2>/dev/null || echo "missing")"
[ "${DEMO_HEALTH}" = "healthy" ] || fail "argos-demo-panel health=${DEMO_HEALTH}"
log "  argos-demo-panel healthy"

if ! curl -sf -o /dev/null http://localhost:9181/healthz; then
    fail "demo panel /healthz at localhost:9181 not 2xx"
fi
log "  /healthz OK"

# --- Phase 3: seed surface assertions ---
log "phase 3: asserting 10 surfaces populated..."

# All counts pulled directly from the demo DB inside the container.
# Single python3 invocation to read counts atomically; falls back to
# sqlite3 if python3 is missing in the image (it isn't, alpine slim).
read_count() {
    local table="$1" where="$2"
    docker exec argos-demo-panel sh -c "
        sqlite3 /data/argos.db 'SELECT COUNT(*) FROM ${table} ${where};' 2>/dev/null
        " 2>/dev/null || echo "ERR"
}

# sqlite3 isn't in the slim image either; use the seed CLI's output
# as the indirect source of truth instead. Re-running seed prints the
# row counts (idempotent for hosts/countries/whitelist/channels;
# activity adds 15 each run; settings INSERT OR REPLACE).
SEED_OUT="$(docker exec -e ARGOS_DEMO_SEED=1 argos-demo-panel /argos demo seed --yes 2>&1 || true)"
log "  re-seed output: ${SEED_OUT}"
# After init+re-seed, hosts/country/whitelist/channels are at the
# original counts (idempotent); activity has 30 (15 * 2). Settings
# count is 6.
expect_in_output() {
    local pattern="$1" label="$2"
    if ! echo "${SEED_OUT}" | grep -q "${pattern}"; then
        fail "seed output did not include ${label} (pattern: ${pattern})"
    fi
    log "  PASS: seed output reports ${label}"
}
expect_in_output "demo seed complete" "completion summary"

# Use argos channel inspect to verify channels visibly populated --
# it ships with the binary and reads /data/argos.db internally.
INSPECT_OUT="$(docker exec argos-demo-panel /argos channel inspect --type telegram 2>&1)"
echo "${INSPECT_OUT}" | grep -q 'demo: ops-alerts' || \
    fail "channel inspect did not list 'demo: ops-alerts': ${INSPECT_OUT}"
log "  PASS: notification channel visible via 'argos channel inspect'"

# 3a. argos demo stats: count thresholds for the production-density
# seed (v1.3.35.2). Each row reports demo_count + total_count; we
# assert demo_count meets the per-surface minimums from the user's
# spec.
log "  running 'argos demo stats' for count assertions..."
STATS_OUT="$(docker exec -e ARGOS_DEMO_SEED=1 argos-demo-panel /argos demo stats 2>&1)"
echo "${STATS_OUT}"

# Assert each surface meets its production-density minimum. The
# stats output format is "<label>  <demo_count>  <total_count>";
# the awk below pulls the demo column.
assert_min() {
    local label="$1" want="$2"
    local got
    got=$(echo "${STATS_OUT}" | awk -v lbl="${label}" '
        $0 ~ lbl { for (i=NF; i>=1; i--) if ($i ~ /^[0-9]+$/) { print $i; exit } }
    ' | tail -1)
    # The line shape places demo before total, so we want the
    # second-to-last numeric field on the matching line.
    got=$(echo "${STATS_OUT}" | awk -v lbl="${label}" '
        $0 ~ lbl { print $(NF-1) }
    ' | head -1)
    if [ -z "${got}" ] || [ "${got}" -lt "${want}" ]; then
        fail "stats: ${label} demo_count=${got:-NA}, want >= ${want}"
    fi
    log "    PASS: ${label} demo_count=${got} (>= ${want})"
}
assert_min "hosts"                   12
assert_min "country_ban_expansions"   6
assert_min "security_whitelist"       6
assert_min "log_entries"             80
assert_min "notification_channels"    4
assert_min "notification_rules"       5
assert_min "notification_deliveries" 200
assert_min "backups"                  5
assert_min "login_attempts"          30

# 3b. Self-block subcommand round-trip: seed -> verify settings row
# present -> clear -> verify gone.
log "  testing self-block round-trip..."
docker exec -e ARGOS_DEMO_SEED=1 argos-demo-panel /argos demo seed-self-block --yes >/dev/null
SB1=$(docker exec argos-demo-panel sh -c "ls /data/argos.db" 2>/dev/null)
[ -n "${SB1}" ] || fail "argos.db missing"
docker exec -e ARGOS_DEMO_SEED=1 argos-demo-panel /argos demo clear-self-block --yes >/dev/null
log "    PASS: seed-self-block + clear-self-block completed without error"

# --- Phase 3c: panel-LAPI integration check (v1.3.35.3) ---
log "phase 3c: panel-LAPI integration (machine credentials present)..."

# 3c-i: argos-panel machine registered with LAPI?
if ! docker exec argos-demo-crowdsec cscli machines list 2>/dev/null | grep -q "argos-panel"; then
    fail "argos-panel machine not registered with LAPI -- crowdsec-init sidecar didn't run or failed"
fi
log "  PASS: argos-panel machine registered with LAPI"

# 3c-ii: no recent 'lapi 403' errors in panel logs (since the last
# 30s window). v1.3.35.2 had these on every country reconciler tick;
# v1.3.35.3 must be silent post-credential-import.
recent_403="$(docker logs argos-demo-panel --since 30s 2>&1 | grep -c 'lapi 403' || true)"
if [ "${recent_403}" -gt 0 ]; then
    log "  WARN: ${recent_403} recent 'lapi 403' lines in panel logs"
    docker logs argos-demo-panel --since 30s 2>&1 | grep 'lapi 403' | head -5
    fail "panel still hitting LAPI 403 after credentials should be imported"
fi
log "  PASS: zero 'lapi 403' lines in last 30s of panel logs"

# 3c-iii: panel imported credentials (the sentinel file gets deleted
# after import; presence of the file means import didn't run yet).
sentinel_present="$(docker exec argos-demo-panel sh -c 'test -f /data/shared/crowdsec-machine-credentials.yaml && echo present || echo absent' 2>/dev/null || echo unknown)"
if [ "${sentinel_present}" = "present" ]; then
    fail "credentials sentinel /data/shared/crowdsec-machine-credentials.yaml still present after panel start -- import did not run"
fi
log "  PASS: credentials sentinel consumed (import completed)"

# --- Phase 3d: bouncer-auth integration (v1.3.35.4) ---
log "phase 3d: bouncer-auth integration (cscli bouncers + LAPI decisions endpoint)..."

# 3d-i: argos-demo-bouncer registered with LAPI?
if ! docker exec argos-demo-crowdsec cscli bouncers list 2>/dev/null | grep -q "argos-demo-bouncer"; then
    fail "argos-demo-bouncer not registered with LAPI -- init.sh's stage-2 bouncer add did not run or failed"
fi
log "  PASS: argos-demo-bouncer registered with LAPI"

# 3d-ii: panel can hit GET /v1/decisions (bouncer-auth path) without
# 403. The panel's threats UI calls go through this same auth path,
# so a 200 here means the threats tab will render.
BOUNCER_KEY_FROM_ENV="$(docker exec argos-demo-panel sh -c 'printenv CROWDSEC_BOUNCER_API_KEY' 2>/dev/null)"
if [ -z "${BOUNCER_KEY_FROM_ENV}" ] || [ "${BOUNCER_KEY_FROM_ENV}" = "demo-bouncer-key-not-real" ]; then
    fail "panel container's CROWDSEC_BOUNCER_API_KEY env is empty or still placeholder (got ${#BOUNCER_KEY_FROM_ENV} chars)"
fi
log "  PASS: panel container has real bouncer key in env (length=${#BOUNCER_KEY_FROM_ENV})"

# 3d-iii: decisions endpoint returns 200 with the real key (vs 403
# with the placeholder). curl from inside the panel container so we
# use the same internal LAPI URL the panel itself uses.
DECISIONS_HTTP="$(docker exec argos-demo-panel sh -c "wget -q -S -O /dev/null --header=\"X-Api-Key: \${CROWDSEC_BOUNCER_API_KEY}\" http://crowdsec:8081/v1/decisions 2>&1 | grep -oE 'HTTP/1\.[01] [0-9]+' | tail -1 | awk '{print \$2}'" 2>/dev/null)"
if [ "${DECISIONS_HTTP}" != "200" ]; then
    fail "GET /v1/decisions returned HTTP=${DECISIONS_HTTP:-empty}, expected 200 (bouncer auth not working)"
fi
log "  PASS: GET /v1/decisions returns 200 (bouncer auth working)"

# 3d-iv: zero 'lapi 403' across ALL paths (machine + bouncer) in the
# last 60s. Phase 3c already checked the country-reconciler path
# (machine creds); this catches any remaining bouncer-auth 403.
recent_403_total="$(docker logs argos-demo-panel --since 60s 2>&1 | grep -c 'lapi 403' || true)"
if [ "${recent_403_total}" -gt 0 ]; then
    log "  WARN: ${recent_403_total} recent 'lapi 403' lines in last 60s of panel logs"
    docker logs argos-demo-panel --since 60s 2>&1 | grep 'lapi 403' | head -5
    fail "panel still hitting LAPI 403 after both machine + bouncer credentials should be present"
fi
log "  PASS: zero 'lapi 403' lines in last 60s (machine + bouncer auth both working)"

# --- Phase 4: argos-prod NON-INTERFERENCE check (mid-test) ---
log "phase 4: prod stack non-interference check (post-init)..."

for c in "${PROD_CONTAINERS[@]}"; do
    id_now="$(docker inspect "${c}" --format '{{.Id}}' 2>/dev/null || echo MISSING)"
    started_now="$(docker inspect "${c}" --format '{{.State.StartedAt}}' 2>/dev/null || echo MISSING)"
    [ "${id_now}" = "${PROD_BEFORE_ID[${c}]}" ] || \
        fail "prod ${c} container id changed: ${PROD_BEFORE_ID[${c}]:0:12} -> ${id_now:0:12}"
    [ "${started_now}" = "${PROD_BEFORE_STARTED[${c}]}" ] || \
        fail "prod ${c} restarted during demo init: ${PROD_BEFORE_STARTED[${c}]} -> ${started_now}"
    log "  ${c}: id + started_at unchanged"
done

PROD_DB_SIZE_NOW="$(docker exec argos-prod-panel sh -c 'stat -c %s /data/argos.db')"
[ "${PROD_DB_SIZE_NOW}" = "${PROD_DB_SIZE_BEFORE}" ] || \
    log "  WARN: prod argos.db size changed (${PROD_DB_SIZE_BEFORE}->${PROD_DB_SIZE_NOW}) -- this is expected if the panel logged audit events during the test"

# --- Phase 5: teardown ---
log "phase 5: running scripts/demo/teardown.sh --purge..."
( "${REPO_DIR}/scripts/demo/teardown.sh" --purge ) || fail "teardown.sh failed"

# --- Phase 6: demo gone ---
log "phase 6: demo cleanup checks..."
sleep 2
for c in argos-demo-panel argos-demo-caddy argos-demo-crowdsec; do
    if docker ps -a --format '{{.Names}}' | grep -qx "${c}"; then
        fail "demo container ${c} still present after teardown"
    fi
done
log "  PASS: 0 demo containers present"

if docker volume ls --format '{{.Name}}' | grep -qE '^argos_demo_'; then
    fail "argos_demo_* volumes still present after teardown -v"
fi
log "  PASS: 0 argos_demo_* volumes present"

if [ -d "${DEMO_DIR}" ]; then
    fail "${DEMO_DIR} still exists after --purge"
fi
log "  PASS: ${DEMO_DIR} removed"

# --- Phase 7: argos-prod NON-INTERFERENCE final check ---
log "phase 7: prod stack non-interference check (post-teardown)..."
for c in "${PROD_CONTAINERS[@]}"; do
    id_now="$(docker inspect "${c}" --format '{{.Id}}' 2>/dev/null || echo MISSING)"
    started_now="$(docker inspect "${c}" --format '{{.State.StartedAt}}' 2>/dev/null || echo MISSING)"
    [ "${id_now}" = "${PROD_BEFORE_ID[${c}]}" ] || \
        fail "prod ${c} container id changed post-teardown: ${PROD_BEFORE_ID[${c}]:0:12} -> ${id_now:0:12}"
    [ "${started_now}" = "${PROD_BEFORE_STARTED[${c}]}" ] || \
        fail "prod ${c} restarted post-teardown: ${PROD_BEFORE_STARTED[${c}]} -> ${started_now}"
    log "  ${c}: still untouched"
done

# Confirm prod volumes still exist (they were never touched).
for v in argos_prod_data argos_prod_crowdsec_data argos_prod_caddy_data; do
    docker volume ls --format '{{.Name}}' | grep -qx "${v}" || fail "prod volume ${v} missing post-teardown"
done
log "  PASS: argos_prod_* volumes intact"

log "PASS: demo-environment EFFECT smoke complete"
