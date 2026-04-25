#!/bin/sh
# check-no-personal-data.sh -- fails if committed docs / code / configs
# leak operator-specific information.
#
# Run from the repo root:
#
#   ./scripts/check-no-personal-data.sh
#
# Wired into CI (see .github/workflows/) and recommended as a
# pre-commit hook. The check runs on docs/, the top-level CHANGELOG
# and ARCHITECTURE files, the Go source under backend/, and the React
# source under frontend/src/. It deliberately skips:
#
#   - .git/                       commit history is immutable; rewriting
#                                 would break published tags
#   - node_modules/, vendor/      third-party content not under our
#                                 control
#   - site/, dist/                build output -- regenerated, not the
#                                 source of truth
#   - mkdocs.yml site_url /
#     repo_url / site_author      the actual public docs URL + handle;
#                                 documenting the publisher of the
#                                 docs portal is intentional
#   - github.com/cmos486/         the public repo URL; required by Go
#       argos-edge                module imports and as the canonical
#                                 link from README badges + docs
#
# The patterns below are the operator-specific data that v1.3.15
# scrubbed. Adding new placeholders here is the contract for keeping
# argos-edge committable as a public project.
set -e

cd "$(dirname "$0")/.." || exit 1

# Files to scan: docs + ARCHITECTURE + CHANGELOG + backend Go + frontend
# TS/TSX. Everything else is third-party or build output.
INCLUDES='--include=*.md --include=*.go --include=*.tsx --include=*.ts'
INCLUDES="$INCLUDES --include=*.yaml --include=*.yml --include=*.json"
EXCLUDES='--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=vendor'
EXCLUDES="$EXCLUDES --exclude-dir=site --exclude-dir=dist --exclude-dir=static"
# Two files document the sanitization itself and must be allowed to
# name the patterns being scrubbed:
#   - this script (it spells out its own regexes in comments + code)
#   - docs/release-notes/v1.3.15.md (the meta-doc for the cleanup)
# Adding more entries here is a deliberate exception, not a default.
EXCLUDES="$EXCLUDES --exclude=check-no-personal-data.sh"
EXCLUDES="$EXCLUDES --exclude=v1.3.15.md"

# Pattern A: any subdomain or apex of cmos486.es that is NOT the
# github.io docs URL (cmos486.github.io). This catches both the
# explicit per-service homelab subdomains (archive.cmos486.es,
# casa.cmos486.es, ...) and any future leak.
CMOS486_ES=$(grep -rEn 'cmos486\.es' $INCLUDES $EXCLUDES . 2>/dev/null \
              | grep -v 'cmos486\.github\.io' \
              || true)

# Pattern B: operator-specific RFC 1918 ranges seen in v1.3.x smoke
# tests (192.168.3.X = panel/services LAN; 192.168.5.X = client side).
# RFC 5737 documentation ranges (192.0.2/24, 198.51.100/24,
# 203.0.113/24) and Docker bridges (172.18.0/16, 172.20.0/16) and the
# generic /16 examples (192.168.0.0/16, 192.168.1.1) are NOT operator-
# specific and stay un-flagged.
LAN_IPS=$(grep -rEn '192\.168\.3\.[0-9]+|192\.168\.5\.[0-9]+' \
            $INCLUDES $EXCLUDES . 2>/dev/null || true)

# Pattern C: operator personal email (gmail address used in commit
# author lines pre-v1.3.15). Commit authors are out of scope for this
# check (immutable history); but any leak into committed files is a
# regression.
GMAIL=$(grep -rEn 'discodurovirtualk' $INCLUDES $EXCLUDES . 2>/dev/null \
          || true)

FOUND=0
if [ -n "$CMOS486_ES" ]; then
    printf '\n[FAIL] operator domain (cmos486.es) leaked:\n%s\n' "$CMOS486_ES"
    FOUND=1
fi
if [ -n "$LAN_IPS" ]; then
    printf '\n[FAIL] operator LAN IPs leaked:\n%s\n' "$LAN_IPS"
    FOUND=1
fi
if [ -n "$GMAIL" ]; then
    printf '\n[FAIL] operator personal email leaked:\n%s\n' "$GMAIL"
    FOUND=1
fi

if [ "$FOUND" = 1 ]; then
    cat <<'EOF'

Use placeholders documented in CONTRIBUTING.md:
  - Domains : example.com, *.example.com (RFC 2606)
  - LAN IPs : 192.0.2.X, 198.51.100.X, 203.0.113.X (RFC 5737)
  - Emails  : ops@example.com, admin@example.com

If a hit is a false positive (rare; the patterns are deliberately narrow)
update this script with a documented exception alongside the new entry.
EOF
    exit 1
fi

echo "[OK] no operator-specific data found in committed sources"
