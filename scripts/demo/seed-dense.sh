#!/bin/bash
# scripts/demo/seed-dense.sh
#
# Writes a production-density log_entries table into the running demo
# stack (500k rows over 7 days by default, raw of ~1.5 KB per access
# row) so long writes and the 7 d dashboard can be gated on the demo
# before they touch prod. Strike 13 (v1.3.40.2) rule: no release that
# adds a long write ships without running that write against this
# seed first.
#
# Wraps `argos demo seed-dense` inside argos-demo-panel; the profile
# (share per source / day / hour, status, method, duration, size, host
# ranks, path / IP / UA cardinality, error families) is in
# backend/cmd/argos/cli_demo_dense.go and comes from read-only
# aggregate SELECTs on prod (2026-09-26). Deterministic per --seed.
#
# Usage:
#   scripts/demo/seed-dense.sh [--rows N] [--days N] [--seed N]
#   scripts/demo/seed-dense.sh --clear
#
# Pre-flight: the demo panel must be running and `argos demo seed`
# must have populated the hosts table (init.sh does both). Refuses to
# run without 1.5 x the expected DB growth free on the docker volume
# filesystem (1.3 GB of DB per 500k rows; the WAL is checkpointed
# every 4 MB during the load, and a re-seed after --clear reuses the
# file's free pages).
#
# Exit codes: 0 seeded, 1 pre-flight failed, 2 seed command failed.

set -euo pipefail

ROWS=500000
DAYS=7
SEED=1
CLEAR=0
PANEL="${ARGOS_DEMO_PANEL_CONTAINER:-argos-demo-panel}"

while [ $# -gt 0 ]; do
    case "$1" in
        --rows) ROWS="$2"; shift 2 ;;
        --days) DAYS="$2"; shift 2 ;;
        --seed) SEED="$2"; shift 2 ;;
        --clear) CLEAR=1; shift ;;
        -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

log()  { printf '[demo/seed-dense] %s\n' "$*"; }
fail() { printf '[demo/seed-dense] FAIL: %s\n' "$*" >&2; exit 1; }

case "${PANEL}" in
    *prod*) fail "refusing to touch a container named ${PANEL}" ;;
esac
docker inspect "${PANEL}" --format '{{.State.Running}}' 2>/dev/null | grep -q true \
    || fail "${PANEL} is not running (scripts/demo/init.sh first)"

db_size() {
    docker exec "${PANEL}" sh -c 'stat -c %s /data/argos.db 2>/dev/null || echo 0'
}

if [ "${CLEAR}" = "1" ]; then
    before="$(db_size)"
    docker exec -e ARGOS_DEMO_SEED=1 "${PANEL}" /argos demo clear-dense --yes || exit 2
    log "db size before=${before} after=$(db_size) (VACUUM not run; the file keeps its pages)"
    exit 0
fi

# Free-space gate on the volume filesystem, as seen from inside the
# container (same filesystem as the docker volume).
need_kb=$(( ROWS * 1300 / 500000 * 1024 * 15 / 10 ))
free_kb="$(docker exec "${PANEL}" sh -c "df -Pk /data | awk 'NR==2 {print \$4}'")"
[ "${free_kb}" -ge "${need_kb}" ] \
    || fail "need ${need_kb} KB free for ${ROWS} rows (1.5 x growth), have ${free_kb} KB"

hosts="$(docker exec -e ARGOS_DEMO_SEED=1 "${PANEL}" /argos demo stats 2>/dev/null | grep -E '^hosts' | grep -oE '[0-9]+' | head -1 || echo 0)"
[ "${hosts:-0}" -gt 0 ] || fail "hosts table is empty; run 'argos demo seed' (init.sh) first"

before="$(db_size)"
log "seeding ${ROWS} rows over ${DAYS} days (seed=${SEED}) into ${PANEL}..."
start="$(date +%s)"
docker exec -e ARGOS_DEMO_SEED=1 "${PANEL}" /argos demo seed-dense --yes \
    --rows "${ROWS}" --days "${DAYS}" --seed "${SEED}" || exit 2
end="$(date +%s)"
log "wall time $(( end - start )) s; db size before=${before} after=$(db_size) bytes"
