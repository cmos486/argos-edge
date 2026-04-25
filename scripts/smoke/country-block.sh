#!/bin/bash
# scripts/smoke/country-block.sh
#
# Verifies country-based blocking actually works end-to-end against
# a live argos-prod stack. Exists because v1.3.17 / v1.3.19 silently
# dropped Country decisions at the Caddy edge -- cscli decisions
# list reported the country ban as active; matching requests still
# returned 200/304.
#
# EXPECTED RESULT BY RELEASE
# ==========================
# Until v1.3.21 lands the panel-side Country -> Range expansion,
# this script will FAIL when run against any argos-edge stack
# v1.3.20 or older, even with `enable_streaming: false` confirmed
# in runtime config. THIS IS EXPECTED -- the script is the
# regression test for the bug v1.3.21 fixes.
#
#   v1.3.17 .. v1.3.19  -- FAIL (panel emits no enable_streaming)
#   v1.3.20             -- FAIL (panel emits enable_streaming:false
#                                but upstream plugin still rejects
#                                scope=Country in both stream and
#                                live mode -- see project memory
#                                + docs/release-notes/v1.3.20.md)
#   v1.3.21+            -- PASS (panel expands Country bans to
#                                Range decisions, which the plugin
#                                handles natively)
#
# So a FAIL here on v1.3.20 is NOT a regression -- it is the
# correct signal. The PASS oracle activates with v1.3.21.
#
# Run it after every change to the country-blocking path so the
# real-world behavior cannot drift from what release notes claim.
#
# Usage:
#   TEST_COUNTRY=XX TEST_IP=<ip> TEST_HOST=<https-url> \
#     ./scripts/smoke/country-block.sh [crowdsec-container]
#
# Defaults are placeholders (RFC 5737 docs ranges + ISO 3166 "XX")
# so committing this file leaks no operator data. Operator overrides
# every variable to match their stack; see argument list below.
#
# Arguments:
#   $1 -- name of the running CrowdSec container.
#         Default: argos-prod-crowdsec.
#
# Environment:
#   TEST_COUNTRY  ISO 3166-1 alpha-2 of the country to ban (test
#                 country only -- do not use one that overlaps with
#                 your operator audience). Default: XX.
#   TEST_IP       Public IPv4 address that GeoLite2 resolves to
#                 TEST_COUNTRY. The script sends this in
#                 X-Forwarded-For; argos's trusted_proxies must be
#                 configured for the loopback / docker bridge hop
#                 to honour it (this is the v1.3.18 default).
#                 Default: 192.0.2.1 (RFC 5737, GeoLite2 returns
#                 unknown -- script will FAIL with default; this is
#                 intentional so a bare run does not pretend to
#                 verify anything).
#   TEST_HOST     Full https URL of an argos-served host. Default:
#                 https://example.com (placeholder; will fail DNS).
#
# Exit codes:
#   0  PASS  -- got 403, country blocking works.
#   1  FAIL  -- got non-403, fix is regressed (or never landed).
#   2  SETUP -- prerequisite missing (container not running, cscli
#               unreachable, defaults still in place, etc).
#
# Cleanup:
#   trap unconditionally deletes the test decision on exit. If the
#   script is killed mid-run, manual cleanup:
#     docker exec <container> cscli decisions delete \
#         --scope Country --value <TEST_COUNTRY>

set -euo pipefail

CROWDSEC_CONTAINER="${1:-argos-prod-crowdsec}"
TEST_COUNTRY="${TEST_COUNTRY:-XX}"
TEST_IP="${TEST_IP:-192.0.2.1}"
TEST_HOST="${TEST_HOST:-https://example.com}"

log()  { printf '[smoke/country-block] %s\n' "$*"; }
fail() { printf '[smoke/country-block] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() { printf '[smoke/country-block] SETUP: %s\n' "$*" >&2; exit 2; }

# Refuse to run with the placeholder defaults. A bare invocation
# would otherwise return some confusing exit code without the
# operator realising they verified nothing.
if [ "${TEST_COUNTRY}" = "XX" ] || [ "${TEST_IP}" = "192.0.2.1" ] || [ "${TEST_HOST}" = "https://example.com" ]; then
    setup_fail "TEST_COUNTRY / TEST_IP / TEST_HOST are still placeholders. Export real values before running."
fi

# Sanity: container must be running.
if ! docker ps --format '{{.Names}}' | grep -qx "${CROWDSEC_CONTAINER}"; then
    setup_fail "container ${CROWDSEC_CONTAINER} is not running"
fi

cleanup() {
    log "cleanup: removing test decision"
    docker exec "${CROWDSEC_CONTAINER}" cscli decisions delete \
        --scope Country --value "${TEST_COUNTRY}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "[1/4] adding Country=${TEST_COUNTRY} ban (5 min)"
docker exec "${CROWDSEC_CONTAINER}" cscli decisions add \
    --scope Country --value "${TEST_COUNTRY}" \
    --duration 5m --reason "argos smoke: country-block verification" \
    >/dev/null

# 16s covers the v1.3.20-default 15s ticker_interval plus a
# little slack. Without enable_streaming: false this wait is
# pointless (the bouncer never indexes Country decisions in
# stream mode), but the wait stays here so the test fails for
# the right reason if streaming gets re-enabled.
log "[2/4] waiting 16s for bouncer to pick up the decision"
sleep 16

log "[3/4] probing ${TEST_HOST} with XFF=${TEST_IP} (resolves to ${TEST_COUNTRY})"
STATUS=$(curl -sk -o /dev/null -w '%{http_code}' \
    -H "X-Forwarded-For: ${TEST_IP}" \
    "${TEST_HOST}/")

log "[4/4] response: HTTP ${STATUS}"

if [ "${STATUS}" = "403" ]; then
    log "PASS: country blocking enforced (got 403 from ${TEST_COUNTRY}-resolving IP)"
    exit 0
fi

fail "expected 403, got ${STATUS} -- country blocking NOT working. Likely cause: enable_streaming defaulted to true (v1.3.17/v1.3.19 bug) or the panel did not reload the Caddy config."
