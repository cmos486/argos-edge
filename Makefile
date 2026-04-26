# argos-edge Makefile
#
# Operator-facing convenience targets that wrap the
# scripts/sync-prod.sh + docker compose + smoke flow. Documented
# in docs/operations/deployment.md. The targets exist because
# v1.3.25's prod-smoke caught the dual-dir deploy gap (panel
# image at vN, bind-mounted setup-appsec.sh stuck at vM<N).
#
# Convention: every target is a one-line wrapper around a
# script or docker compose command. Logic lives in the scripts;
# the Makefile is glue.

ARGOS_PROD_DIR ?= $(HOME)/argos-prod

# Scripts are colocated with the source repo. The Makefile lives
# at the repo root so $(CURDIR) resolves to the source dir
# regardless of where `make` was invoked from.
SYNC_SCRIPT       := $(CURDIR)/scripts/sync-prod.sh
SMOKE_SYNC        := $(CURDIR)/scripts/smoke/sync-prod.sh
SMOKE_SCENARIOS   := $(CURDIR)/scripts/smoke/scenarios-toggle.sh
SMOKE_APPSEC      := $(CURDIR)/scripts/smoke/appsec-tuning.sh
SMOKE_COUNTRY     := $(CURDIR)/scripts/smoke/country-block.sh

.PHONY: help sync-prod sync-prod-dry deploy-prod verify-prod smoke-self

help:
	@echo "argos-edge operator targets:"
	@echo ""
	@echo "  make sync-prod          rsync this checkout into ARGOS_PROD_DIR"
	@echo "                          (defaults to ~/argos-prod). Diff-first"
	@echo "                          preview + interactive confirmation."
	@echo "  make sync-prod-dry      same as sync-prod but --dry-run only."
	@echo "  make deploy-prod        sync-prod (auto-confirm) + docker compose"
	@echo "                          build + up. The single-command upgrade"
	@echo "                          path for releases that touch bind-"
	@echo "                          mounted files (crowdsec/* / Caddyfile)."
	@echo "  make verify-prod        run the post-deploy smoke scripts"
	@echo "                          (scenarios + appsec + country) against"
	@echo "                          the running prod stack."
	@echo "  make smoke-self         run the sync-prod self-smoke against"
	@echo "                          tmp dirs (safe, no prod side-effects)."
	@echo ""
	@echo "Environment:"
	@echo "  ARGOS_PROD_DIR          operational dir (default: ~/argos-prod)"
	@echo "  ARGOS_SESSION_TOKEN     panel session cookie for verify-prod"
	@echo "  CROWDSEC_CONTAINER      default: argos-prod-crowdsec"
	@echo "  PANEL_BASE_URL          default: http://localhost:9180"

sync-prod:
	@ARGOS_PROD_DIR="$(ARGOS_PROD_DIR)" $(SYNC_SCRIPT)

sync-prod-dry:
	@ARGOS_PROD_DIR="$(ARGOS_PROD_DIR)" $(SYNC_SCRIPT) --dry-run

deploy-prod:
	@echo "[deploy-prod] Step 1: sync source to operational dir"
	@ARGOS_PROD_DIR="$(ARGOS_PROD_DIR)" $(SYNC_SCRIPT) --yes
	@echo
	@echo "[deploy-prod] Step 2: docker compose build (in operational dir)"
	@cd "$(ARGOS_PROD_DIR)" && docker compose build argos
	@echo
	@echo "[deploy-prod] Step 3: docker compose up -d --force-recreate argos"
	@cd "$(ARGOS_PROD_DIR)" && docker compose up -d --force-recreate --no-deps argos
	@echo
	@echo "[deploy-prod] done. Run 'make verify-prod' to smoke the deploy."

verify-prod:
	@if [ -z "$$ARGOS_SESSION_TOKEN" ]; then \
		echo "[verify-prod] ARGOS_SESSION_TOKEN required. Capture via:" >&2; \
		echo '  SESSION=$$(docker run --rm -v argos_prod_data:/data alpine sh -c "apk add --no-cache sqlite >/dev/null 2>&1; sqlite3 /data/argos.db \"SELECT token FROM sessions WHERE expires_at > datetime('"'"'now'"'"') ORDER BY id DESC LIMIT 1;\"")' >&2; \
		echo '  ARGOS_SESSION_TOKEN=$$SESSION make verify-prod' >&2; \
		exit 2; \
	fi
	@echo "[verify-prod] scenarios-toggle.sh"
	@$(SMOKE_SCENARIOS)
	@echo
	@echo "[verify-prod] appsec-tuning.sh"
	@$(SMOKE_APPSEC)
	@echo
	@echo "[verify-prod] PASS"

smoke-self:
	@$(SMOKE_SYNC)
