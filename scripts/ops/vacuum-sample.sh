#!/bin/bash
# scripts/ops/vacuum-sample.sh
#
# Passive sampler for the panel's monthly VACUUM (retention.go
# maybeVacuum: day 1 of the month, hour 04 UTC). Prepared 2026-09-28
# for the 2026-10-01 run; NOT installed anywhere, the operator decides.
#
# What it records, from the host, without touching the stack:
#   - hosts.txt   GET /api/hosts every 100 ms: epoch, HTTP code,
#                 time_total (s). Uses the newest live session token from
#                 the DB volume (the verify-prod recipe); with no live
#                 session it samples /healthz instead and says so.
#   - stats.txt   docker stats of the panel every 5 s (CPU %, memory).
#   - size.txt    argos.db and argos.db-wal sizes every 5 s.
#   - vacuum.txt  the panel log lines "vacuum completed" / "vacuum failed"
#                 with their timestamps, plus the cgroup cpu.stat before
#                 and after.
#   - summary.txt p50 / p99 / max of hosts.txt, max CPU, max WAL, file
#                 size before / after, and whether the VACUUM ran.
#
# Stops by itself: STOP_AFTER_S (default 2400 = 40 min, so 03:58 to
# 04:38 UTC) or 120 s after the panel logs the VACUUM result, whichever
# comes first.
#
# Precondition: the panel runs v1.3.42.3 or later (calendar slots, the
# 1st at 04:00 UTC, catch-up at boot; `logs.vacuum.last_at` in the
# settings table says when it last ran). On v1.3.42.2 and earlier the
# check ran on a 24 h ticker from the boot time and only fired when a
# tick landed in hour 04 UTC. The sampler reports "VACUUM did not run"
# either way; it does not trigger anything.
#
# Suggested cron line (root, or a user with sudo -n and docker):
#   58 3 1 * * /home/claude/argos-edge/scripts/ops/vacuum-sample.sh >> /var/tmp/argos-vacuum-cron.log 2>&1
#
# Env:
#   ARGOS_URL              (default http://127.0.0.1:9180)
#   ARGOS_PANEL_CONTAINER  (default argos-prod-panel)
#   ARGOS_DATA_VOLUME      (default argos_prod_data)
#   OUT_DIR                (default /var/tmp/argos-vacuum-<UTC date>)
#   STOP_AFTER_S           (default 2400)
#   HOSTS_INTERVAL         (default 0.1)
#
# Exit codes: 0 sampled (see summary.txt for the verdict), 2 precondition.
set -u
URL="${ARGOS_URL:-http://127.0.0.1:9180}"
P="${ARGOS_PANEL_CONTAINER:-argos-prod-panel}"
VOL="${ARGOS_DATA_VOLUME:-argos_prod_data}"
OUT="${OUT_DIR:-/var/tmp/argos-vacuum-$(date -u +%Y%m%d)}"
STOP_AFTER_S="${STOP_AFTER_S:-2400}"
HOSTS_INTERVAL="${HOSTS_INTERVAL:-0.1}"
log() { echo "[vacuum-sample] $(date -u +%H:%M:%S) $*"; }

command -v docker >/dev/null 2>&1 || { log "docker missing" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { log "python3 missing" >&2; exit 2; }
docker inspect "$P" >/dev/null 2>&1 || { log "container $P not found" >&2; exit 2; }
DBDIR=$(docker volume inspect "$VOL" --format '{{.Mountpoint}}' 2>/dev/null) || { log "volume $VOL not found" >&2; exit 2; }
SUDO=""
if [ ! -r "$DBDIR/argos.db" ]; then
  if sudo -n test -r "$DBDIR/argos.db" 2>/dev/null; then SUDO="sudo -n"; else log "cannot read $DBDIR/argos.db (run as root or with sudo -n)" >&2; exit 2; fi
fi
mkdir -p "$OUT" || { log "cannot create $OUT" >&2; exit 2; }
CID=$(docker inspect "$P" --format '{{.Id}}')
CG="/sys/fs/cgroup/system.slice/docker-${CID}.scope"

# Session token: newest live session, read-only, or /healthz.
TOKEN=$(docker run --rm -v "${VOL}:/data:ro" alpine:3.20 sh -c "apk add -q sqlite >/dev/null 2>&1; sqlite3 -readonly /data/argos.db \"SELECT token FROM sessions WHERE expires_at > datetime('now') ORDER BY id DESC LIMIT 1;\"" 2>/dev/null | tail -1)
if [ -n "$TOKEN" ]; then
  SAMPLE_URL="$URL/api/hosts"; HDR="Cookie: argos_session=${TOKEN}"
  log "sampling $SAMPLE_URL with the newest live session"
else
  SAMPLE_URL="$URL/healthz"; HDR="X-Argos-Sampler: 1"
  log "no live session in the DB; sampling $SAMPLE_URL instead (no DB read on that path)"
fi
echo "sample_url=$SAMPLE_URL" > "$OUT/summary.txt"

t0=$(date +%s)
size_of() { $SUDO stat -c %s "$1" 2>/dev/null || echo 0; }
{
  echo "start $(date -u +%FT%TZ)"
  echo "db_before $(size_of "$DBDIR/argos.db") wal_before $(size_of "$DBDIR/argos.db-wal")"
  echo "cpu_stat_before: $(tr '\n' ' ' < "$CG/cpu.stat" 2>/dev/null)"
} >> "$OUT/vacuum.txt"

# 1. /api/hosts (or /healthz) every HOSTS_INTERVAL.
(
  while :; do
    printf '%s ' "$(date +%s.%N | cut -c1-14)" >> "$OUT/hosts.txt"
    curl -s -m 30 -o /dev/null -w '%{http_code} %{time_total}\n' -H "$HDR" "$SAMPLE_URL" >> "$OUT/hosts.txt" 2>&1
    sleep "$HOSTS_INTERVAL"
  done
) & H_PID=$!

# 2. docker stats and sizes every 5 s; the panel log for the verdict.
(
  while :; do
    ts=$(date -u +%FT%TZ)
    docker stats --no-stream --format "$ts {{.CPUPerc}} {{.MemUsage}}" "$P" >> "$OUT/stats.txt" 2>/dev/null
    echo "$ts db=$(size_of "$DBDIR/argos.db") wal=$(size_of "$DBDIR/argos.db-wal")" >> "$OUT/size.txt"
    sleep 5
  done
) & S_PID=$!

done_at=""
while :; do
  now=$(date +%s)
  if [ -z "$done_at" ]; then
    line=$(docker logs --since "$(date -u -d "@$t0" +%FT%TZ)" "$P" 2>&1 | grep -E '"msg":"vacuum (completed|failed)"' | tail -1)
    if [ -n "$line" ]; then
      done_at=$now
      echo "panel: $line" >> "$OUT/vacuum.txt"
      log "panel logged the VACUUM result; sampling 120 s more"
    fi
  elif [ $((now - done_at)) -ge 120 ]; then
    break
  fi
  [ $((now - t0)) -ge "$STOP_AFTER_S" ] && { log "stop after ${STOP_AFTER_S} s"; break; }
  sleep 2
done
kill "$H_PID" "$S_PID" 2>/dev/null; wait "$H_PID" "$S_PID" 2>/dev/null

{
  echo "db_after $(size_of "$DBDIR/argos.db") wal_after $(size_of "$DBDIR/argos.db-wal")"
  echo "cpu_stat_after: $(tr '\n' ' ' < "$CG/cpu.stat" 2>/dev/null)"
  echo "end $(date -u +%FT%TZ)"
} >> "$OUT/vacuum.txt"

python3 - "$OUT" >> "$OUT/summary.txt" <<'EOF'
import sys, os, re
out = sys.argv[1]
def q(xs, p):
    if not xs: return 0.0
    xs = sorted(xs); i = min(len(xs) - 1, max(0, int(round(p / 100 * (len(xs) - 1)))))
    return xs[i]
lat, codes = [], {}
for l in open(os.path.join(out, "hosts.txt")):
    parts = l.split()
    if len(parts) >= 3:
        codes[parts[1]] = codes.get(parts[1], 0) + 1
        try: lat.append(float(parts[2]) * 1000)
        except ValueError: pass
print(f"samples={len(lat)} codes={codes}")
print(f"latency_ms p50={q(lat,50):.1f} p99={q(lat,99):.1f} max={max(lat) if lat else 0:.1f} over_50ms={sum(1 for x in lat if x > 50)}")
cpu = []
for l in open(os.path.join(out, "stats.txt")):
    m = re.search(r"\s([\d.]+)%", l)
    if m: cpu.append(float(m.group(1)))
print(f"panel_cpu_pct max={max(cpu) if cpu else 0} samples={len(cpu)}")
wal = []
for l in open(os.path.join(out, "size.txt")):
    m = re.search(r"wal=(\d+)", l)
    if m: wal.append(int(m.group(1)))
print(f"wal_bytes max={max(wal) if wal else 0}")
v = open(os.path.join(out, "vacuum.txt")).read()
print("vacuum_ran=" + ("yes" if "vacuum completed" in v else ("failed" if "vacuum failed" in v else "no (see the precondition in the script header)")))
for l in v.splitlines():
    if l.startswith(("db_before", "db_after", "panel:")): print(l)
EOF
log "done; summary:"; cat "$OUT/summary.txt"
