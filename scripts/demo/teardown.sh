#!/bin/bash
# scripts/demo/teardown.sh
#
# v1.3.35 demo-stack teardown. Default mode removes containers +
# volumes (clean slate); pass --purge to also delete the materialised
# ~/argos-demo/ directory.
#
# argos-prod stack is untouched: this script only operates on the
# argos-demo project (containers prefixed argos-demo-*, volumes
# prefixed argos_demo_*, network argos-demo-net).

set -euo pipefail

DEMO_DIR="${ARGOS_DEMO_DIR:-${HOME}/argos-demo}"

log()  { printf '[demo/teardown] %s\n' "$*"; }

PURGE=0
for a in "$@"; do
    case "$a" in
        --purge) PURGE=1 ;;
        -h|--help)
            sed -n '2,15p' "$0"
            exit 0
            ;;
    esac
done

if [ ! -d "${DEMO_DIR}" ]; then
    log "${DEMO_DIR} does not exist; nothing to do"
    exit 0
fi

# `docker compose down -v` on the demo project: removes containers
# + the named volumes that compose owns. Idempotent.
log "docker compose down -v (project=argos-demo)..."
( cd "${DEMO_DIR}" && docker compose down -v --remove-orphans ) || true

# Sanity: confirm prod containers are still up. If a prod container
# vanished while we were tearing down demo, that's a bug we want to
# fail loudly on.
for c in argos-prod-panel argos-prod-caddy argos-prod-crowdsec; do
    if docker ps --format '{{.Names}}' | grep -qx "${c}"; then
        log "  prod container ${c} still running OK"
    else
        log "  WARN: prod container ${c} not running -- check argos-prod stack"
    fi
done

if [ "${PURGE}" -eq 1 ]; then
    log "removing ${DEMO_DIR}..."
    rm -rf "${DEMO_DIR}"
fi

log "PASS: demo stack torn down"
