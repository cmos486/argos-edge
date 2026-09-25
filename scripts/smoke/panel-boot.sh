#!/bin/bash
# scripts/smoke/panel-boot.sh
#
# v1.3.38.3 EFFECT smoke for the panel boot path. Read-only: it does
# NOT restart anything; it reads the current container's boot log
# (docker logs keeps it from the last (re)create) and asserts on the
# timestamps the panel itself wrote.
#
# EFFECT verified:
#   1. boot-to-listen: "argos starting" -> "http listening" takes at
#      most MAX_BOOT_SECONDS (default 1). Before v1.3.38.3 the boot
#      retention purge held the single SQLite connection ~1.5 s while
#      the rest of the boot queued behind it (1.75 s on prod).
#   2. the first "retention purge done" (if any rows needed purging)
#      is logged AFTER "http listening", at least MIN_PURGE_DELAY
#      seconds later (default 100; BootPurgeDelay is 120 s). When the
#      container is younger than BootPurgeDelay the check is skipped
#      with a note instead of failing.
#
# Usage:
#   scripts/smoke/panel-boot.sh                       # container argos-prod-panel
#   ARGOS_PANEL_CONTAINER=argos-demo-panel scripts/smoke/panel-boot.sh
#
# Env:
#   ARGOS_PANEL_CONTAINER  (default argos-prod-panel)
#   MAX_BOOT_SECONDS       (default 1)
#   MIN_PURGE_DELAY        (default 100)
#
# Exit codes: 0 PASS, 1 FAIL, 2 precondition (container / log lines missing)
set -u
C="${ARGOS_PANEL_CONTAINER:-argos-prod-panel}"
MAXB="${MAX_BOOT_SECONDS:-1}"
MINP="${MIN_PURGE_DELAY:-100}"

command -v docker >/dev/null 2>&1 || { echo "[panel-boot] docker missing" >&2; exit 2; }
started=$(docker inspect "$C" --format '{{.State.StartedAt}}' 2>/dev/null) || { echo "[panel-boot] container $C not found" >&2; exit 2; }

# docker logs --timestamps prefixes each line with an RFC3339Nano stamp.
logs=$(docker logs --timestamps --since "$started" "$C" 2>&1)
ts_of() { # first line whose msg matches $1 -> epoch seconds with fraction
  printf '%s\n' "$logs" | grep -F "\"msg\":\"$1\"" | head -1 | cut -d' ' -f1 \
    | python3 -c 'import sys,datetime; s=sys.stdin.read().strip(); print(datetime.datetime.fromisoformat(s[:26]+"+00:00").timestamp() if s else "")'
}
t_start=$(ts_of "argos starting"); t_listen=$(ts_of "http listening"); t_purge=$(ts_of "retention purge done")
[ -n "$t_start" ] && [ -n "$t_listen" ] || { echo "[panel-boot] boot markers not found in $C logs" >&2; exit 2; }

rc=0
boot=$(python3 -c "print(round($t_listen - $t_start, 3))")
if python3 -c "import sys; sys.exit(0 if $boot <= $MAXB else 1)"; then
  echo "[panel-boot] boot-to-listen ${boot}s (<= ${MAXB}s) PASS"
else
  echo "[panel-boot] boot-to-listen ${boot}s (> ${MAXB}s) FAIL"; rc=1
fi

age=$(python3 -c "import time; print(round(time.time() - $t_start))")
if [ -n "$t_purge" ]; then
  delay=$(python3 -c "print(round($t_purge - $t_listen, 1))")
  if python3 -c "import sys; sys.exit(0 if $delay >= $MINP else 1)"; then
    echo "[panel-boot] first purge ${delay}s after listen (>= ${MINP}s) PASS"
  else
    echo "[panel-boot] first purge ${delay}s after listen (< ${MINP}s) FAIL"; rc=1
  fi
elif [ "$age" -lt 130 ]; then
  echo "[panel-boot] container is ${age}s old; purge check skipped (BootPurgeDelay not reached yet)"
else
  echo "[panel-boot] no purge logged yet after ${age}s (nothing to purge, or purge > ${MINP}s away): OK"
fi

[ $rc -eq 0 ] && echo "[panel-boot] PASS" || echo "[panel-boot] FAIL"
exit $rc
