#!/bin/bash
# scripts/smoke/threats-page-bytes.sh
#
# v1.3.38.5 EFFECT smoke for the server-paged Threats table.
#
# Feature under test: frontend/src/pages/Threats.tsx asks
# GET /api/threats/decisions?page=N&per_page=100 with every filter
# applied server-side, and its 15 s auto-refresh re-requests only the
# page in view and only while the tab is visible. Before v1.3.38.5 the
# page pulled the whole LAPI decision list (7.2 MB on the operator's
# CAPI-enrolled prod, 24k rows) every 15 s and on every keystroke.
#
# EFFECT verified: with a real browser tab sitting on /threats in the
# foreground, the bytes the panel sends in reply to
# GET /api/threats/decisions[?...] over a WINDOW-second window stay
# under MAX_BYTES, and the number of such requests under MAX_REQUESTS
# (one on load + one per 15 s tick: 5 in 60 s). Baseline on 1.3.38.4:
# 7.2 MB x (4-5) = ~29-36 MB per 60 s at prod density.
#
# How it counts (server-side, no browser is driven by this script):
# like dashboard-refetch-loop.sh it taps the docker bridge of the
# panel's compose network with a passive AF_PACKET socket (python3
# stdlib, needs sudo). A TCP connection becomes "attributed" when a
# request line for ARGOS_PATH is seen on it and stops being attributed
# at the next request line on the same connection (browsers do not
# pipeline), so the payload bytes flowing back from the panel on an
# attributed connection are that endpoint's response bytes (headers
# included). Plain HTTP only (lan mode). Nothing is sent or modified.
#
# Usage:
#   sudo scripts/smoke/threats-page-bytes.sh                 # 60 s window
#   ARGOS_PANEL_CONTAINER=argos-demo-panel WINDOW=60 MAX_BYTES=1000000 \
#     sudo scripts/smoke/threats-page-bytes.sh
#
# The operator opens /threats in a browser BEFORE starting the window
# and keeps the tab in the foreground for the whole window.
#
# Env:
#   ARGOS_PANEL_CONTAINER  panel container name (default argos-prod-panel)
#   ARGOS_PANEL_PORT       container port of the panel (default 8080)
#   WINDOW                 seconds to count (default 60)
#   MAX_BYTES              PASS threshold on response bytes, inclusive
#                          (default 1000000: 1 MB for a 60 s window)
#   MAX_REQUESTS           PASS threshold on request count, inclusive
#                          (default 8)
#   ARGOS_PATH             request path to attribute (default
#                          /api/threats/decisions)
#
# Exit codes:
#   0  PASS: bytes <= MAX_BYTES and requests <= MAX_REQUESTS
#   1  FAIL: either threshold exceeded
#   2  precondition failed (not root, no python3, capture error)
set -u

CONTAINER="${ARGOS_PANEL_CONTAINER:-argos-prod-panel}"
PORT="${ARGOS_PANEL_PORT:-8080}"
WINDOW="${WINDOW:-60}"
MAX_BYTES="${MAX_BYTES:-1000000}"
MAX_REQ="${MAX_REQUESTS:-8}"
REQ_PATH="${ARGOS_PATH:-/api/threats/decisions}"

if [ "$(id -u)" -ne 0 ]; then
  echo "[threats-bytes] must run as root (AF_PACKET capture); use sudo" >&2
  exit 2
fi
command -v python3 >/dev/null 2>&1 || { echo "[threats-bytes] python3 missing" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "[threats-bytes] docker missing" >&2; exit 2; }

NET=$(docker inspect "$CONTAINER" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null)
CIP=$(docker inspect "$CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
NETID=$(docker network inspect "$NET" --format '{{.Id}}' 2>/dev/null)
IFACE="br-${NETID:0:12}"
if [ -z "$CIP" ] || [ -z "$NETID" ] || ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "[threats-bytes] cannot resolve container ip / bridge for ${CONTAINER} (ip='${CIP}' iface='${IFACE}')" >&2
  exit 2
fi

echo "[threats-bytes] attributing 'GET ${REQ_PATH}' replies from ${CIP}:${PORT} on ${IFACE} for ${WINDOW}s (PASS if bytes <= ${MAX_BYTES} and requests <= ${MAX_REQ})"

OUT=$(python3 - "$PORT" "$WINDOW" "$REQ_PATH" "$CIP" "$IFACE" <<'PY'
import socket, struct, sys, time
port = int(sys.argv[1]); window = float(sys.argv[2]); path = sys.argv[3]
panel_ip = socket.inet_aton(sys.argv[4]); iface = sys.argv[5]
needle = ("GET " + path + " ").encode()
needle_q = ("GET " + path + "?").encode()
methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ")
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind((iface, 0))
s.settimeout(0.5)
deadline = time.time() + window
attributed = {}  # (client ip, client port) -> True while the last request on it was ours
requests = 0
resp_bytes = 0
while time.time() < deadline:
    try:
        frame = s.recv(65535)
    except socket.timeout:
        continue
    if len(frame) < 34:
        continue
    eth_type = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if eth_type == 0x8100:
        eth_type = struct.unpack("!H", frame[16:18])[0]; off = 18
    if eth_type != 0x0800:
        continue
    ihl = (frame[off] & 0x0F) * 4
    if frame[off + 9] != 6:
        continue
    src_ip = frame[off + 12:off + 16]; dst_ip = frame[off + 16:off + 20]
    tcp = off + ihl
    if len(frame) < tcp + 20:
        continue
    sport, dport = struct.unpack("!HH", frame[tcp:tcp + 4])
    doff = ((frame[tcp + 12] >> 4) & 0x0F) * 4
    payload = frame[tcp + doff:]
    if not payload:
        continue
    if dst_ip == panel_ip and dport == port:
        conn = (src_ip, sport)
        if payload.startswith(needle) or payload.startswith(needle_q):
            attributed[conn] = True
            requests += 1
        elif payload.startswith(methods):
            attributed[conn] = False
    elif src_ip == panel_ip and sport == port:
        if attributed.get((dst_ip, dport)):
            resp_bytes += len(payload)
print(requests, resp_bytes)
PY
)
rc=$?
set -- $OUT
if [ $rc -ne 0 ] || [ $# -ne 2 ] || ! [[ "$1" =~ ^[0-9]+$ ]] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
  echo "[threats-bytes] capture failed (rc=$rc, out='$OUT')" >&2
  exit 2
fi
REQS=$1; BYTES=$2
if [ "$REQS" -gt 0 ]; then AVG=$((BYTES / REQS)); else AVG=0; fi
echo "[threats-bytes] ${REQS} request(s), ${BYTES} response byte(s) in ${WINDOW}s (avg ${AVG} B/request)"
if [ "$BYTES" -le "$MAX_BYTES" ] && [ "$REQS" -le "$MAX_REQ" ]; then
  echo "[threats-bytes] PASS"
  exit 0
fi
echo "[threats-bytes] FAIL: bytes ${BYTES} > ${MAX_BYTES} or requests ${REQS} > ${MAX_REQ}"
exit 1
