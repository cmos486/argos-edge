#!/bin/bash
# scripts/smoke/waf-sources-agree.sh
#
# v1.3.39 EFFECT smoke: the panel's WAF signal agrees with CrowdSec.
#
# Feature under test: the unified WAF events provider. The Dashboard
# security section, the Security overview and the AppSec page all
# count "WAF events (AppSec)" from ONE cached LAPI fetch, defined as
# alerts with kind=waf (one per blocked / detected request, "hits")
# plus the appsec-* ban scenarios of kind=crowdsec ("bans"). Before
# v1.3.39 the Dashboard and the overview read the waf_audit table,
# which has had no producer since the per-host Coraza WAF was turned
# off (2026-04-25), so they said 0 while AppSec blocked hundreds of
# requests a day.
#
# EFFECT verified: over the last 24 h, four independent readings of
# the same number agree within TOLERANCE percent and are all > 0:
#   D  GET /api/dashboard/security?range=24h  -> waf_engines.appsec.events
#   O  GET /api/security/overview             -> appsec_hits_24h + appsec_bans_24h
#   A  GET /api/appsec/metrics?window=24h     -> total_hits
#   L  LAPI, exact filters through cscli in the crowdsec container:
#      kind=waf, plus scenario=crowdsecurity/appsec-native and
#      scenario=crowdsecurity/crowdsec-appsec-outofband, --since 24h
# The comparison is relative to L. Caches (30 s) and the seconds
# between the four calls make a small drift normal; 1 % is the gate
# (v1.3.39.1: 5 % until the 2 % gap was explained, the out-of-band
# ban scenario missing from the panel's prefix test).
#
# Usage:
#   ARGOS_SESSION_TOKEN=<argos_session cookie value> \
#   [ARGOS_URL=http://127.0.0.1:9180] [ARGOS_CROWDSEC_CONTAINER=argos-prod-crowdsec] \
#   [TOLERANCE=1] scripts/smoke/waf-sources-agree.sh
#
# Exit codes:
#   0  PASS: all four > 0 and within TOLERANCE % of L
#   1  FAIL: a source is 0 or diverges
#   2  precondition failed (no token, non-200, docker/cscli error)
set -u

URL="${ARGOS_URL:-http://127.0.0.1:9180}"
TOKEN="${ARGOS_SESSION_TOKEN:-}"
CS="${ARGOS_CROWDSEC_CONTAINER:-argos-prod-crowdsec}"
TOL="${TOLERANCE:-1}"

[ -n "$TOKEN" ] || { echo "[waf-sources] ARGOS_SESSION_TOKEN required" >&2; exit 2; }
for c in curl docker python3; do command -v $c >/dev/null 2>&1 || { echo "[waf-sources] $c missing" >&2; exit 2; }; done

get() { curl -s -w '\n%{http_code}' -H "Cookie: argos_session=${TOKEN}" "${URL}${1}"; }
field() { # body, python expression over json d
  python3 -c "import json,sys; d=json.load(sys.stdin); print(int($1))" 2>/dev/null
}

read_json() { # path, expr, label -> prints the number or exits 2
  out=$(get "$1"); code=$(printf '%s' "$out" | tail -1); body=$(printf '%s' "$out" | sed '$d')
  [ "$code" = "200" ] || { echo "[waf-sources] $1 returned $code" >&2; exit 2; }
  n=$(printf '%s' "$body" | field "$2")
  [ -n "$n" ] || n=0
  echo "$n"
}

D=$(read_json "/api/dashboard/security?range=24h" "((d.get('waf_engines') or {}).get('appsec') or {}).get('events', 0)") || exit 2
O=$(read_json "/api/security/overview" "d.get('appsec_hits_24h', 0) + d.get('appsec_bans_24h', 0)") || exit 2
A=$(read_json "/api/appsec/metrics?window=24h" "d.get('total_hits', 0)") || exit 2

RAW=$(docker exec "$CS" cscli alerts list --since 24h -l 0 -o raw 2>/dev/null) || { echo "[waf-sources] cscli alerts list failed in $CS" >&2; exit 2; }
L=$(printf '%s\n' "$RAW" | awk -F, 'NR>1 && ($NF=="waf" || $4=="crowdsecurity/appsec-native" || $4=="crowdsecurity/crowdsec-appsec-outofband"){n++} END{print n+0}')
LW=$(printf '%s\n' "$RAW" | awk -F, 'NR>1 && $NF=="waf"{n++} END{print n+0}')

echo "[waf-sources] 24h: dashboard=$D overview=$O appsec=$A lapi=$L (kind=waf $LW + appsec-* bans $((L-LW)))"

fail=0
[ "$L" -gt 0 ] || { echo "[waf-sources] LAPI has no AppSec alerts in 24 h; nothing to compare" >&2; exit 2; }
for pair in "dashboard:$D" "overview:$O" "appsec:$A"; do
  name=${pair%%:*}; v=${pair##*:}
  if [ "$v" -le 0 ]; then echo "[waf-sources] FAIL: $name reports 0 while LAPI has $L"; fail=1; continue; fi
  diff=$(( v > L ? v - L : L - v ))
  pct=$(( diff * 100 / L ))
  if [ "$pct" -gt "$TOL" ]; then echo "[waf-sources] FAIL: $name=$v diverges from LAPI=$L by ${pct}% (> ${TOL}%)"; fail=1; else echo "[waf-sources] $name=$v within ${pct}% of LAPI"; fi
done
[ $fail -eq 0 ] && { echo "[waf-sources] PASS"; exit 0; }
exit 1
