#!/bin/bash
# scripts/smoke/sync-prod.sh
#
# Self-smoke for scripts/sync-prod.sh. Runs against ephemeral
# tmpdirs -- never touches the operator's real ~/argos-prod or
# ~/argos-edge -- so this script is safe to run on any host
# with a checkout of argos-edge.
#
# Smoke gates (matching the v1.3.26 plan):
#   1. Refuses to run with invalid paths (clear error).
#   2. No-op when SRC + DST are byte-identical (exit 0).
#   3. Drift detection: SRC has a new file → preview shows it;
#      apply with --yes propagates it.
#   4. Operator-managed files protected: docker-compose.override.yml
#      and .env in DST survive a sync from a SRC that doesn't
#      have them.
#   5. Excludes work: data / build outputs / .git in SRC don't
#      land in DST.
#
# Exit 0 on PASS, 1 on FAIL, 2 on setup error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYNC_SCRIPT="${SCRIPT_DIR}/../sync-prod.sh"

log()  { printf '[smoke/sync-prod] %s\n' "$*"; }
fail() { printf '[smoke/sync-prod] FAIL: %s\n' "$*" >&2; exit 1; }

[ -x "${SYNC_SCRIPT}" ] || { echo "missing ${SYNC_SCRIPT}"; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# Helper: build a fake repo at $1 with the minimum-viable
# argos-edge shape sync-prod expects (top-level
# docker-compose.yml + scripts/sync-prod.sh + a couple of
# bind-mounted files for realism).
make_repo() {
    local d="$1"
    mkdir -p "${d}/crowdsec/appsec-configs" "${d}/scripts"
    cat > "${d}/docker-compose.yml" <<'YAML'
services:
  argos: { image: stub }
YAML
    echo "echo stub" > "${d}/crowdsec/setup-appsec.sh"
    echo "name: stub" > "${d}/crowdsec/appsec-configs/argos-appsec-block.yaml"
    echo "Caddyfile-stub" > "${d}/Caddyfile"
    cp "${SYNC_SCRIPT}" "${d}/scripts/sync-prod.sh"
    chmod +x "${d}/scripts/sync-prod.sh"
}

# === gate 1: invalid paths produce clear errors =============
log "[1/5] invalid paths produce clear errors"

# DST missing.
SRC_OK="${WORK}/src1"
make_repo "${SRC_OK}"
if ARGOS_PROD_DIR=/no/such/path/ever "${SRC_OK}/scripts/sync-prod.sh" --dry-run --yes 2>/tmp/sp-err.txt; then
    fail "sync-prod accepted a missing DST"
fi
grep -q "operational dir missing" /tmp/sp-err.txt \
    || fail "missing-DST error message changed: $(cat /tmp/sp-err.txt)"

# SRC == DST should refuse.
SAME="${WORK}/same"
make_repo "${SAME}"
if ARGOS_PROD_DIR="${SAME}" "${SAME}/scripts/sync-prod.sh" --dry-run --yes 2>/tmp/sp-err.txt; then
    fail "sync-prod accepted SRC=DST"
fi
grep -q "same path" /tmp/sp-err.txt \
    || fail "SRC=DST error changed: $(cat /tmp/sp-err.txt)"

# DST that doesn't look like argos (no docker-compose.yml).
NOT_ARGOS="${WORK}/not-argos"
mkdir -p "${NOT_ARGOS}"
echo "random" > "${NOT_ARGOS}/random.txt"
if ARGOS_PROD_DIR="${NOT_ARGOS}" "${SRC_OK}/scripts/sync-prod.sh" --dry-run --yes 2>/tmp/sp-err.txt; then
    fail "sync-prod accepted DST without docker-compose.yml"
fi
grep -q "does not look like an argos operational dir" /tmp/sp-err.txt \
    || fail "non-argos-DST error changed: $(cat /tmp/sp-err.txt)"

# === gate 2: no-op when in sync =============================
log "[2/5] no-op when SRC + DST are byte-identical"
SRC2="${WORK}/src2"
DST2="${WORK}/dst2"
make_repo "${SRC2}"
mkdir -p "${DST2}"
cp -r "${SRC2}/." "${DST2}/"
OUT=$(ARGOS_PROD_DIR="${DST2}" "${SRC2}/scripts/sync-prod.sh" --yes 2>&1)
echo "${OUT}" | grep -q "no changes" \
    || fail "no-op path missed: ${OUT}"

# === gate 3: drift detection + apply ========================
log "[3/5] drift detection: new file in SRC propagates on apply"
SRC3="${WORK}/src3"
DST3="${WORK}/dst3"
make_repo "${SRC3}"
mkdir -p "${DST3}"
cp -r "${SRC3}/." "${DST3}/"
echo "v1.3.26-only" > "${SRC3}/scripts/new-file.sh"
ARGOS_PROD_DIR="${DST3}" "${SRC3}/scripts/sync-prod.sh" --yes >/dev/null 2>&1 \
    || fail "apply path errored unexpectedly"
[ -f "${DST3}/scripts/new-file.sh" ] \
    || fail "new file did not propagate to DST"
grep -q "v1.3.26-only" "${DST3}/scripts/new-file.sh" \
    || fail "new file content wrong"

# === gate 4: operator-managed files protected ===============
log "[4/5] operator-managed files protected from sync"
SRC4="${WORK}/src4"
DST4="${WORK}/dst4"
make_repo "${SRC4}"
mkdir -p "${DST4}"
cp -r "${SRC4}/." "${DST4}/"
# Operator-only files in DST that SRC doesn't have.
echo "image: argos:v1.3.99" > "${DST4}/docker-compose.override.yml"
echo "ARGOS_MASTER_KEY=secret-do-not-leak" > "${DST4}/.env"
# Force a real sync by adding something to SRC.
echo "trigger" > "${SRC4}/Caddyfile"
ARGOS_PROD_DIR="${DST4}" "${SRC4}/scripts/sync-prod.sh" --yes >/dev/null 2>&1 \
    || fail "sync errored unexpectedly"
[ -f "${DST4}/docker-compose.override.yml" ] \
    || fail "operator override file got deleted"
grep -q "argos:v1.3.99" "${DST4}/docker-compose.override.yml" \
    || fail "operator override file got rewritten"
[ -f "${DST4}/.env" ] \
    || fail ".env got deleted"
grep -q "ARGOS_MASTER_KEY=secret-do-not-leak" "${DST4}/.env" \
    || fail ".env got rewritten"

# === gate 5: excludes keep build outputs / VCS state out =====
log "[5/5] build outputs / .git / data in SRC do not propagate to DST"
SRC5="${WORK}/src5"
DST5="${WORK}/dst5"
make_repo "${SRC5}"
mkdir -p "${DST5}"
cp -r "${SRC5}/." "${DST5}/"
mkdir -p \
    "${SRC5}/frontend/dist" \
    "${SRC5}/backend/static/assets" \
    "${SRC5}/.git" \
    "${SRC5}/data" \
    "${SRC5}/node_modules"
echo "build" > "${SRC5}/frontend/dist/index.js"
echo "asset" > "${SRC5}/backend/static/assets/x.js"
echo "ref"   > "${SRC5}/.git/HEAD"
echo "row"   > "${SRC5}/data/argos.db"
echo "dep"   > "${SRC5}/node_modules/x.js"
# Trigger a real sync.
echo "trigger" > "${SRC5}/Caddyfile"
ARGOS_PROD_DIR="${DST5}" "${SRC5}/scripts/sync-prod.sh" --yes >/dev/null 2>&1 \
    || fail "sync errored unexpectedly"
[ ! -d "${DST5}/frontend/dist" ] \
    || fail "frontend/dist leaked into DST"
[ ! -d "${DST5}/backend/static/assets" ] \
    || fail "backend/static/assets leaked into DST"
[ ! -d "${DST5}/.git" ] \
    || fail ".git leaked into DST"
[ ! -d "${DST5}/data" ] \
    || fail "data/ leaked into DST"
[ ! -d "${DST5}/node_modules" ] \
    || fail "node_modules/ leaked into DST"

log "PASS: all 5 sync-prod gates green"
