#!/bin/bash
# scripts/smoke/true-detect-mode.sh
#
# v1.3.29 smoke gate: per-host true_detect_mode end-to-end.
# Panel toggle -> reconciler writes profiles.yaml sentinel ->
# setup-appsec.sh splices the block + restarts crowdsec ->
# alerts targeting the host get suppressed at the profile-
# evaluation layer (no LAPI decisions created).
#
# Why synthetic LAPI alert injection (not real AppSec attack):
# the empirical mid-impl finding (v1.3.29 spike PHASE 1) showed
# that inband AppSec alerts on the argos block-config arrive
# with remediation=null and the bucketing scenario
# crowdsecurity/crowdsec-appsec-outofband only consumes events
# with evt.Appsec.HasOutBandMatches == true (port 7423 listener).
# The current argos stack routes everything to the inband
# listener (port 7422), so a real-attack-burst smoke would see
# 0 decisions in BOTH detect-on and detect-off phases -- a false
# positive that does not validate the feature.
#
# Synthetic LAPI POST bypasses the listener config and directly
# tests the profile-filter logic in isolation. The alert is
# crafted with the same shape a real outofband-scenario overflow
# would produce (source.scope=Ip, remediation=true,
# events[0].meta carries target_fqdn). default_ip_remediation
# would create a ban from that alert; the argos_true_detect_mode
# profile is tested by whether it suppresses that ban.
#
# Verifies EFFECT (smoke verifies effect, not specs per the
# working agreement v1.3.20+ memo).
#
# Usage:
#   PANEL_BASE_URL=http://localhost:9180 \
#   ARGOS_SESSION_TOKEN=<cookie value> \
#   CROWDSEC_CONTAINER=argos-prod-crowdsec \
#   TEST_HOST=detect.example.com \
#     ./scripts/smoke/true-detect-mode.sh
#
# TEST_HOST must already exist in the panel hosts table; the
# script does NOT create or delete hosts.
#
# Tunables:
#   TEST_IP             RFC5737 documentation IP for the alert's
#                       source.value (default 203.0.113.42)
#   CROWDSEC_RESTART_WAIT
#                       seconds to wait after setup-appsec.sh's
#                       SIGTERM-driven container restart for the
#                       new profiles.yaml to load (default 15)
#   ALERT_PROPAGATE_WAIT
#                       seconds between the LAPI POST and the
#                       decision-creation check (default 5)
#
# Exit codes:
#   0 = both phases pass: detect-on suppresses, detect-off bans
#   1 = some assertion diverged from expected state
#   2 = setup error (missing env, host not found, etc.)

set -euo pipefail

PANEL_BASE_URL="${PANEL_BASE_URL:-http://localhost:9180}"
ARGOS_SESSION_TOKEN="${ARGOS_SESSION_TOKEN:-}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-argos-prod-crowdsec}"
TEST_HOST="${TEST_HOST:-}"
TEST_IP="${TEST_IP:-203.0.113.42}"
CROWDSEC_RESTART_WAIT="${CROWDSEC_RESTART_WAIT:-15}"
ALERT_PROPAGATE_WAIT="${ALERT_PROPAGATE_WAIT:-5}"

log()  { printf '[smoke/true-detect-mode] %s\n' "$*"; }
fail() { printf '[smoke/true-detect-mode] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() {
    printf '[smoke/true-detect-mode] SETUP: %s\n' "$*" >&2
    exit 2
}

[ -n "${ARGOS_SESSION_TOKEN}" ] || setup_fail "ARGOS_SESSION_TOKEN required"
[ -n "${TEST_HOST}" ] || setup_fail "TEST_HOST required (existing host domain on this stack)"
docker ps --format '{{.Names}}' | grep -qx "${CROWDSEC_CONTAINER}" \
    || setup_fail "container ${CROWDSEC_CONTAINER} is not running"
command -v jq >/dev/null 2>&1 || setup_fail "jq required"
command -v curl >/dev/null 2>&1 || setup_fail "curl required"

# Resolve TEST_HOST -> host id via API. The toggle endpoint takes
# the integer id, not the domain.
HOST_JSON=$(curl -fsS \
    -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
    "${PANEL_BASE_URL}/api/hosts" 2>&1)
HOST_ID=$(echo "${HOST_JSON}" | jq -r ".[] | select(.domain == \"${TEST_HOST}\") | .id")
[ -n "${HOST_ID}" ] && [ "${HOST_ID}" != "null" ] \
    || setup_fail "host ${TEST_HOST} not found via /api/hosts"

# Capture pre-test state so cleanup can restore it.
PREV_DETECT=$(echo "${HOST_JSON}" | jq -r ".[] | select(.id == ${HOST_ID}) | .true_detect_mode")
log "test host: ${TEST_HOST} (id=${HOST_ID}); pre-test true_detect_mode=${PREV_DETECT}"

update_true_detect_mode() {
    # The hosts endpoint is PUT (full replace). Fetch current
    # state, flip the one field, send the whole payload back.
    local target="$1"
    local body
    body=$(echo "${HOST_JSON}" | jq --argjson id "${HOST_ID}" --argjson val "${target}" \
        '.[] | select(.id == $id) |
         {
            domain, target_group_id, tls_mode, tls_email,
            enabled, auth_required, lan_only, true_detect_mode,
            tls_acme_ca_url, tls_challenge, tls_dns_provider
         } | .true_detect_mode = $val')
    curl -fsS -X PUT \
        -H "Cookie: argos_session=${ARGOS_SESSION_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "${body}" \
        "${PANEL_BASE_URL}/api/hosts/${HOST_ID}"
}

cleanup() {
    log "cleanup: restoring true_detect_mode=${PREV_DETECT} on host ${HOST_ID}"
    update_true_detect_mode "${PREV_DETECT}" >/dev/null 2>&1 || true
    docker exec "${CROWDSEC_CONTAINER}" cscli decisions delete --ip "${TEST_IP}" \
        >/dev/null 2>&1 || true
}
trap cleanup EXIT

ensure_curl_in_crowdsec() {
    # crowdsec ships on alpine without curl. Install once per
    # smoke run; idempotent (apk add no-op when already present).
    docker exec "${CROWDSEC_CONTAINER}" sh -c \
        'command -v curl >/dev/null || apk add --no-cache curl >/dev/null 2>&1' \
        2>/dev/null || setup_fail "could not install curl in ${CROWDSEC_CONTAINER}"
}

# lapi_login authenticates the local cscli machine against LAPI
# and echoes the bearer JWT. Token validity is short (~1h);
# obtained per smoke run.
lapi_login() {
    # Crowdsec's alpine image lacks jq; we parse the JWT out of
    # the JSON response with sed. The login response shape is
    # {"code":200,"expire":"...","token":"<JWT>"} -- the second
    # capture group from `"token":"X"` is the bearer token.
    docker exec "${CROWDSEC_CONTAINER}" sh -c '
        LOGIN=$(grep "^login:" /etc/crowdsec/local_api_credentials.yaml | awk "{print \$2}")
        PASS=$(grep "^password:" /etc/crowdsec/local_api_credentials.yaml | awk "{print \$2}")
        curl -fsS -X POST -H "Content-Type: application/json" \
            -d "{\"machine_id\":\"$LOGIN\",\"password\":\"$PASS\"}" \
            http://127.0.0.1:8081/v1/watchers/login \
        | sed -n "s/.*\"token\":\"\([^\"]*\)\".*/\1/p"
    ' 2>&1
}

# inject_synthetic_alert POSTs a hand-crafted alert that mirrors
# the shape a real outofband-scenario overflow would produce:
# source.scope=Ip, remediation=true, events[0].meta carries
# target_fqdn=TEST_HOST. default_ip_remediation would create a
# ban from this alert; the argos_true_detect_mode profile is the
# only thing capable of suppressing it.
inject_synthetic_alert() {
    local jwt="$1"
    local now
    now=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
    local body
    body=$(cat <<JSON
[{
    "scenario": "argos/v1.3.29-smoke",
    "scenario_hash": "v1329-smoke",
    "scenario_version": "1.0",
    "message": "synthetic v1.3.29 smoke alert",
    "remediation": true,
    "simulated": false,
    "events_count": 1,
    "capacity": 1,
    "leakspeed": "60s",
    "labels": ["smoke"],
    "source": {
        "scope": "Ip",
        "value": "${TEST_IP}",
        "ip": "${TEST_IP}",
        "as_name": "TEST-NET-3",
        "as_number": "0",
        "cn": "ZZ"
    },
    "events": [{
        "timestamp": "${now}",
        "meta": [
            {"key": "target_fqdn", "value": "${TEST_HOST}"},
            {"key": "source_ip", "value": "${TEST_IP}"},
            {"key": "service", "value": "appsec"}
        ]
    }],
    "start_at": "${now}",
    "stop_at": "${now}"
}]
JSON
)
    docker exec -i "${CROWDSEC_CONTAINER}" curl -fsS -X POST \
        -H "Authorization: Bearer ${jwt}" \
        -H "Content-Type: application/json" \
        -d "${body}" \
        http://127.0.0.1:8081/v1/alerts \
        2>&1 | head -c 200
    echo
}

count_decisions_for_test_ip() {
    docker exec "${CROWDSEC_CONTAINER}" cscli decisions list --ip "${TEST_IP}" -o json 2>/dev/null \
        | jq 'length // 0'
}

# count_recent_alerts_for_host returns alerts where source.value
# matches TEST_IP and any event meta carries target_host or
# target_fqdn equal to TEST_HOST. This is the AppSec-alert shape
# regardless of inband (uses target_fqdn) vs outofband-scenario
# (uses target_host) origin -- the v1.3.29 mid-impl finding.
count_recent_alerts_for_host() {
    # jq one-arg any() iterates over the implicit input array.
    # Outer any walks .events; inner walks .meta. Each .meta
    # entry becomes . inside the inner any cond.
    docker exec "${CROWDSEC_CONTAINER}" cscli alerts list \
        --since 2m -o json 2>/dev/null | \
        jq --arg h "${TEST_HOST}" --arg ip "${TEST_IP}" \
            '[.[] | select(
                .source.value == $ip and (
                    (.events // []) | any(
                        (.meta // []) | any(
                            (.key == "target_host" or .key == "target_fqdn") and .value == $h
                        )
                    )
                )
            )] | length // 0'
}

# === phase A: true_detect_mode ON ============================
log "[1/8] PUT true_detect_mode=true on host ${HOST_ID}"
update_true_detect_mode true \
    | jq -e '.true_detect_mode == true' >/dev/null \
    || fail "PUT did not echo true_detect_mode=true"

log "[2/8] verify panel sentinel /shared/argos-managed-profiles.yaml lists ${TEST_HOST}"
SENTINEL=$(docker exec "${CROWDSEC_CONTAINER}" \
    cat /shared/argos-managed-profiles.yaml 2>&1 || true)
echo "${SENTINEL}" | grep -qF "${TEST_HOST}" \
    || fail "${TEST_HOST} missing from sentinel:
${SENTINEL}"

log "[3/8] run setup-appsec.sh -- splices block + restarts crowdsec"
# The script's last action is kill -TERM 1 when profiles.yaml
# changed; docker exec returns non-zero (137 = signal-killed) but
# that is expected. Don't fail on it.
docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh >/tmp/sa.log 2>&1 || true
log "  waiting ${CROWDSEC_RESTART_WAIT}s for crowdsec to come back healthy"
sleep "${CROWDSEC_RESTART_WAIT}"
docker ps --filter "name=${CROWDSEC_CONTAINER}" --format '{{.Status}}' | grep -q healthy \
    || fail "crowdsec did not return to healthy after restart"

# Clear any pre-existing decision for the test IP so the assertion
# isn't poisoned by stale state.
docker exec "${CROWDSEC_CONTAINER}" cscli decisions delete --ip "${TEST_IP}" \
    >/dev/null 2>&1 || true

log "[4/8] inject synthetic LAPI alert (target_fqdn=${TEST_HOST}, source=${TEST_IP})"
ensure_curl_in_crowdsec
JWT=$(lapi_login)
[ -n "${JWT}" ] && [ "${JWT}" != "null" ] || setup_fail "LAPI login failed: ${JWT}"
inject_synthetic_alert "${JWT}" | sed 's/^/  /'

log "  waiting ${ALERT_PROPAGATE_WAIT}s for profile evaluation"
sleep "${ALERT_PROPAGATE_WAIT}"

log "[5/8] assert ALERT exists for ${TEST_HOST} from ${TEST_IP}"
ALERT_COUNT=$(count_recent_alerts_for_host)
[ "${ALERT_COUNT}" -gt 0 ] \
    || fail "synthetic alert did not appear in cscli alerts list -- LAPI POST format may have changed"
log "  ${ALERT_COUNT} alert(s) targeting ${TEST_HOST} from ${TEST_IP}"

log "[6/8] assert NO decision created for ${TEST_IP} (detect-mode oracle)"
DECISION_COUNT=$(count_decisions_for_test_ip)
if [ "${DECISION_COUNT}" -gt 0 ]; then
    docker exec "${CROWDSEC_CONTAINER}" cscli decisions list --ip "${TEST_IP}" 2>&1 | head -10
    fail "expected 0 decisions for ${TEST_IP} with detect mode ON, got ${DECISION_COUNT} -- profile filter did not suppress; pivot to Path B"
fi
log "  PASS: alert logged + zero decisions (filter suppressed default_ip_remediation)"

# === phase B: true_detect_mode OFF ===========================
log "[7/8] PUT true_detect_mode=false; setup-appsec.sh; re-test"
update_true_detect_mode false >/dev/null

docker exec "${CROWDSEC_CONTAINER}" /setup-appsec.sh >/tmp/sa.log 2>&1 || true
sleep "${CROWDSEC_RESTART_WAIT}"
docker ps --filter "name=${CROWDSEC_CONTAINER}" --format '{{.Status}}' | grep -q healthy \
    || fail "crowdsec did not return healthy after toggle-off restart"

# Clear stale state again.
docker exec "${CROWDSEC_CONTAINER}" cscli decisions delete --ip "${TEST_IP}" \
    >/dev/null 2>&1 || true

JWT=$(lapi_login)
[ -n "${JWT}" ] && [ "${JWT}" != "null" ] || setup_fail "LAPI login failed: ${JWT}"
inject_synthetic_alert "${JWT}" | sed 's/^/  /'
sleep "${ALERT_PROPAGATE_WAIT}"

log "[8/8] assert decision IS now created for ${TEST_IP} (default_ip_remediation baseline)"
DECISION_COUNT=$(count_decisions_for_test_ip)
[ "${DECISION_COUNT}" -gt 0 ] \
    || fail "expected at least 1 decision for ${TEST_IP} with detect mode OFF, got 0 -- baseline broken; default_ip_remediation should have fired on remediation=true alert"
log "  ${DECISION_COUNT} decision(s) for ${TEST_IP}; baseline ban path intact"

log "PASS: per-host true_detect_mode end-to-end"
log "  detect ON  -> alert logged, decision suppressed"
log "  detect OFF -> alert logged, decision created"
