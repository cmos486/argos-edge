#!/bin/bash
# scripts/smoke/event-storm.sh
#
# v1.3.42.2 EFFECT smoke: the community-blocklist pull no longer floods
# the notifications event queue. Read-only: it reads the panel and
# crowdsec container logs over the last WINDOW_H hours (default 4, two
# blocklist pulls at the 2 h cadence) and asserts on what the panel
# itself wrote.
#
# Before v1.3.42.2 every pull rewrote about 15,000 CAPI decisions with
# new IDs and the monitor turned each one into a threat_ip_banned event
# against a 1,000-slot queue: 10-12k "notifications: event queue full,
# dropping" WARN lines every 2 h (230k dropped events in 40 h on prod,
# 21 MB of journal per day).
#
# EFFECT verified:
#   1. At least MIN_PULLS (default 2) "community-blocklist : added N
#      entries" lines in the crowdsec log inside the window (the pull
#      happened; without it the check proves nothing).
#   2. Zero "event queue full" lines in the panel log inside the window.
#   3. Reported, not gated: the panel's log volume in the window scaled
#      to MB per day, next to BEFORE_MB_PER_DAY when given (21 on prod
#      before the fix), and the total number of log lines.
#
# Usage:
#   scripts/smoke/event-storm.sh
#   WINDOW_H=6 BEFORE_MB_PER_DAY=21 scripts/smoke/event-storm.sh
#
# Env:
#   ARGOS_PANEL_CONTAINER     (default argos-prod-panel)
#   ARGOS_CROWDSEC_CONTAINER  (default argos-prod-crowdsec)
#   WINDOW_H                  (default 4)
#   MIN_PULLS                 (default 2)
#   BEFORE_MB_PER_DAY         (optional, printed next to the after figure)
#
# Exit codes: 0 PASS, 1 FAIL (queue-full lines found), 2 precondition
# (container missing, panel younger than the window, too few pulls yet).
set -u
P="${ARGOS_PANEL_CONTAINER:-argos-prod-panel}"
CS="${ARGOS_CROWDSEC_CONTAINER:-argos-prod-crowdsec}"
WINDOW_H="${WINDOW_H:-4}"
MIN_PULLS="${MIN_PULLS:-2}"
BEFORE="${BEFORE_MB_PER_DAY:-}"
log() { echo "[event-storm] $*"; }

command -v docker >/dev/null 2>&1 || { log "docker missing" >&2; exit 2; }
started=$(docker inspect "$P" --format '{{.State.StartedAt}}' 2>/dev/null) || { log "container $P not found" >&2; exit 2; }
docker inspect "$CS" >/dev/null 2>&1 || { log "container $CS not found" >&2; exit 2; }

now_s=$(date -u +%s)
started_s=$(python3 -c 'import sys,datetime; s=sys.argv[1]; print(int(datetime.datetime.fromisoformat(s[:26]+"+00:00").timestamp()))' "$started")
age_h=$(( (now_s - started_s) / 3600 ))
ver=$(docker exec "$P" /argos --help 2>/dev/null | head -1)
log "panel ${P} (${ver:-version unknown}) started ${started}, age ${age_h} h; window ${WINDOW_H} h"
if [ "$age_h" -lt "$WINDOW_H" ]; then
  n=$(docker logs --since "$started" "$P" 2>&1 | grep -c 'event queue full')
  log "panel younger than the window: ${n} queue-full lines since start so far; come back at +${WINDOW_H} h"
  exit 2
fi

since=$(date -u -d "@$((now_s - WINDOW_H * 3600))" +%Y-%m-%dT%H:%M:%SZ)
pulls=$(docker logs --since "$since" "$CS" 2>&1 | grep -c 'community-blocklist : added')
log "blocklist pulls in the window (since ${since}): ${pulls} (min ${MIN_PULLS})"
if [ "$pulls" -lt "$MIN_PULLS" ]; then
  log "too few pulls to prove the effect yet"
  exit 2
fi

panel_log=$(docker logs --since "$since" "$P" 2>&1)
full=$(printf '%s\n' "$panel_log" | grep -c 'event queue full')
lines=$(printf '%s\n' "$panel_log" | wc -l)
bytes=$(printf '%s\n' "$panel_log" | wc -c)
mb_day=$(python3 -c "print(round($bytes / 1048576 * 24 / $WINDOW_H, 2))")
log "panel log in the window: ${lines} lines, ${bytes} bytes (${mb_day} MB per day${BEFORE:+; before: ${BEFORE} MB per day})"

if [ "$full" -eq 0 ]; then
  log "queue-full lines in the window: 0 across ${pulls} pulls: PASS"
  exit 0
fi
last=$(printf '%s\n' "$panel_log" | grep 'event queue full' | tail -1)
log "queue-full lines in the window: ${full}: FAIL"
log "last: ${last}"
exit 1
