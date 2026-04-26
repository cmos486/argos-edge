#!/bin/bash
# scripts/smoke/lapi-wal.sh
#
# Asserts CrowdSec's LAPI SQLite is in WAL mode. Catches a
# regression where crowdsec/config.yaml.local loses the
# db_config.use_wal: true setting (added v1.3.28) and the
# LAPI silently reverts to rollback-journal mode.
#
# Why this matters (v1.3.28 dogfood):
# CrowdSec emits a startup warning when WAL is off:
#   "sqlite is not using WAL mode, LAPI might become unresponsive
#    when inserting the community blocklist"
# Without WAL, the community-blocklist sync (~15k rows every ~2h)
# holds an exclusive writer lock and every concurrent reader
# (caddy bouncer + panel /api/security/decisions) stalls 3-4
# seconds. v1.3.26 prod-smoke logged 20+ slow GETs in a single
# CAPI sync window.
#
# Smoke verifies EFFECT:
#   PRAGMA journal_mode -> "wal"
#   docker logs           -> the startup warning is absent
#
# Usage:
#   CROWDSEC_CONTAINER=argos-prod-crowdsec ./scripts/smoke/lapi-wal.sh
#
# Exit codes:
#   0 = WAL active + no startup warning
#   1 = mode is not WAL or warning is present
#   2 = setup error (container missing, sqlite unavailable, etc.)

set -euo pipefail

CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-argos-prod-crowdsec}"

log()  { printf '[smoke/lapi-wal] %s\n' "$*"; }
fail() { printf '[smoke/lapi-wal] FAIL: %s\n' "$*" >&2; exit 1; }
setup_fail() {
    printf '[smoke/lapi-wal] SETUP: %s\n' "$*" >&2
    exit 2
}

if ! docker ps --format '{{.Names}}' | grep -qx "${CROWDSEC_CONTAINER}"; then
    setup_fail "container ${CROWDSEC_CONTAINER} is not running"
fi

log "[1/3] PRAGMA journal_mode == wal"
MODE=$(docker exec "${CROWDSEC_CONTAINER}" sh -c \
    'apk add --no-cache sqlite >/dev/null 2>&1 || true
     sqlite3 /var/lib/crowdsec/data/crowdsec.db "PRAGMA journal_mode;" 2>/dev/null')
if [ "${MODE}" != "wal" ]; then
    fail "journal_mode=${MODE:-<empty>} (expected wal). Check db_config.use_wal in crowdsec/config.yaml.local; restart crowdsec to apply"
fi

log "[2/3] startup warning absent in current container's logs"
# CrowdSec emits the warning only at boot. Scope the log scan to
# the current container instance via .State.StartedAt so a
# regression introduced by THIS boot is caught while logs from
# previous containers (pre-fix) don't false-positive.
START=$(docker inspect "${CROWDSEC_CONTAINER}" \
    --format '{{.State.StartedAt}}' 2>/dev/null)
[ -n "${START}" ] || setup_fail "could not read container StartedAt"
WARNED=$(docker logs --since "${START}" "${CROWDSEC_CONTAINER}" 2>&1 | \
    grep -ci "sqlite is not using WAL mode" || true)
if [ "${WARNED}" -gt 0 ]; then
    fail "found ${WARNED} 'sqlite not using WAL' warning(s) since this container started -- WAL was off at boot"
fi

log "[3/3] WAL sidecar files present (created on first write)"
# .db-wal + .db-shm appear when the first write happens after
# WAL is enabled. They may be absent on a freshly-restarted
# container before any write; this is best-effort.
if docker exec "${CROWDSEC_CONTAINER}" \
       ls /var/lib/crowdsec/data/crowdsec.db-wal \
       >/dev/null 2>&1; then
    log "  .db-wal present (writes have happened post-restart)"
else
    log "  .db-wal absent (no writes yet post-restart -- ok, WAL still active per PRAGMA)"
fi

log "PASS: LAPI on WAL mode; no startup warning"
