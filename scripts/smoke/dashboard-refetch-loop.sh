#!/bin/bash
# scripts/smoke/dashboard-refetch-loop.sh
#
# v1.3.38.0 EFFECT smoke for the Dashboard refetch loop fix.
#
# Feature under test: frontend/src/pages/Dashboard.tsx passes a
# stable `onLoaded` callback to OverviewSection. Before v1.3.38.0
# the callback was an inline arrow, so every completed fetch of
# /api/dashboard/overview re-rendered the parent, changed the
# callback identity, re-ran the effect and fetched again: a tight
# loop at network latency (~12 req/s measured) for as long as the
# tab was open.
#
# EFFECT verified: with a real browser tab sitting on the Dashboard,
# the number of `GET /api/dashboard/overview` requests reaching the
# panel port in a WINDOW-second window is small (the 30 s auto-
# refresh gives ~2-3 per 60 s; the loop gave hundreds).
#
# How it counts (server-side, no browser is driven by this script):
# the prod panel runs in ARGOS_PANEL_MODE=lan, so Caddy never sees
# panel API traffic and the panel binary does not log requests. The
# script therefore taps the docker bridge of the panel's compose
# network with a passive AF_PACKET socket (python3 stdlib, needs
# sudo) and counts TCP segments addressed to the panel container
# (its bridge IP, container port 8080) whose payload starts with the
# request line. Counting on the bridge, post-DNAT, sees LAN-originated
# and host-originated requests alike, exactly once each. Plain HTTP
# only (lan mode); behind_caddy deployments should count in the
# Caddy access log instead. Nothing is sent, nothing is modified.
#
# Usage:
#   sudo scripts/smoke/dashboard-refetch-loop.sh            # 60 s window
#   ARGOS_PANEL_CONTAINER=argos-prod-panel WINDOW=60 MAX_REQUESTS=10 \
#     sudo scripts/smoke/dashboard-refetch-loop.sh
#
# The operator opens the Dashboard in a browser BEFORE starting the
# window and keeps the tab in the foreground for the whole window.
#
# Env:
#   ARGOS_PANEL_CONTAINER  panel container name (default argos-prod-panel)
#   ARGOS_PANEL_PORT       container port of the panel (default 8080)
#   WINDOW             seconds to count (default 60)
#   MAX_REQUESTS       PASS threshold, inclusive (default 10)
#   ARGOS_PATH         request path to count (default /api/dashboard/overview)
#
# Exit codes:
#   0  PASS: count <= MAX_REQUESTS
#   1  FAIL: count >  MAX_REQUESTS (loop still present)
#   2  precondition failed (not root, no python3, capture error)
set -u

CONTAINER="${ARGOS_PANEL_CONTAINER:-argos-prod-panel}"
PORT="${ARGOS_PANEL_PORT:-8080}"
WINDOW="${WINDOW:-60}"
MAX="${MAX_REQUESTS:-10}"
REQ_PATH="${ARGOS_PATH:-/api/dashboard/overview}"

if [ "$(id -u)" -ne 0 ]; then
  echo "[refetch-loop] must run as root (AF_PACKET capture); use sudo" >&2
  exit 2
fi
command -v python3 >/dev/null 2>&1 || { echo "[refetch-loop] python3 missing" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "[refetch-loop] docker missing" >&2; exit 2; }

# Resolve the panel's bridge IP and the bridge interface of its network.
NET=$(docker inspect "$CONTAINER" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null)
CIP=$(docker inspect "$CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
NETID=$(docker network inspect "$NET" --format '{{.Id}}' 2>/dev/null)
IFACE="br-${NETID:0:12}"
if [ -z "$CIP" ] || [ -z "$NETID" ] || ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "[refetch-loop] cannot resolve container ip / bridge for ${CONTAINER} (ip='${CIP}' iface='${IFACE}')" >&2
  exit 2
fi

echo "[refetch-loop] counting 'GET ${REQ_PATH}' to ${CIP}:${PORT} on ${IFACE} for ${WINDOW}s (PASS if <= ${MAX})"

COUNT=$(python3 - "$PORT" "$WINDOW" "$REQ_PATH" "$CIP" "$IFACE" <<'PY'
import socket, struct, sys, time
port = int(sys.argv[1]); window = float(sys.argv[2]); needle = ("GET " + sys.argv[3] + " ").encode()
needle_q = ("GET " + sys.argv[3] + "?").encode()
dst_ip = socket.inet_aton(sys.argv[4]); iface = sys.argv[5]
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind((iface, 0))
s.settimeout(0.5)
deadline = time.time() + window
count = 0
while time.time() < deadline:
    try:
        frame = s.recv(65535)
    except socket.timeout:
        continue
    if len(frame) < 34:
        continue
    eth_type = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if eth_type == 0x8100:  # 802.1Q
        eth_type = struct.unpack("!H", frame[16:18])[0]; off = 18
    if eth_type != 0x0800:
        continue
    ihl = (frame[off] & 0x0F) * 4
    if frame[off + 9] != 6:  # TCP
        continue
    if frame[off + 16:off + 20] != dst_ip:
        continue
    tcp = off + ihl
    if len(frame) < tcp + 20:
        continue
    dport = struct.unpack("!H", frame[tcp + 2:tcp + 4])[0]
    if dport != port:
        continue
    doff = ((frame[tcp + 12] >> 4) & 0x0F) * 4
    payload = frame[tcp + doff:]
    if payload.startswith(needle) or payload.startswith(needle_q):
        count += 1
print(count)
PY
)
rc=$?
if [ $rc -ne 0 ] || ! [[ "$COUNT" =~ ^[0-9]+$ ]]; then
  echo "[refetch-loop] capture failed (rc=$rc, out='$COUNT')" >&2
  exit 2
fi

echo "[refetch-loop] ${COUNT} request(s) in ${WINDOW}s"
if [ "$COUNT" -le "$MAX" ]; then
  echo "[refetch-loop] PASS"
  exit 0
fi
echo "[refetch-loop] FAIL: ${COUNT} > ${MAX} (refetch loop present)"
exit 1
