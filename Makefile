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

.PHONY: help sync-prod sync-prod-dry build-prod-image deploy-prod verify-deploy verify-prod smoke-self

help:
	@echo "argos-edge operator targets:"
	@echo ""
	@echo "  make sync-prod          rsync this checkout into ARGOS_PROD_DIR"
	@echo "                          (defaults to ~/argos-prod). Diff-first"
	@echo "                          preview + interactive confirmation."
	@echo "  make sync-prod-dry      same as sync-prod but --dry-run only."
	@echo "  make build-prod-image   docker build the panel image, tagged"
	@echo "                          argos-prod-argos:<argosVersion> with"
	@echo "                          ldflags-injected commit + built_at."
	@echo "                          Updates the override.yml image: line."
	@echo "  make deploy-prod        sync-prod (--yes) + build-prod-image +"
	@echo "                          docker compose up --force-recreate."
	@echo "                          The single-command upgrade path."
	@echo "  make verify-deploy      assert the deployed binary version"
	@echo "                          matches argosVersion (binary +"
	@echo "                          /api/system/version surfaces)."
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

build-prod-image:
	@VER=$$(grep -oE 'argosVersion = "[^"]+"' backend/cmd/argos/main.go | head -1 | cut -d'"' -f2); \
	if [ -z "$$VER" ]; then \
		echo "[build-prod-image] FAIL: could not parse argosVersion from main.go" >&2; \
		exit 1; \
	fi; \
	COMMIT=$$(git rev-parse --short HEAD 2>/dev/null || echo ""); \
	BUILT=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	echo "[build-prod-image] version=$$VER commit=$$COMMIT built=$$BUILT"; \
	cd "$(ARGOS_PROD_DIR)" && docker build \
		--build-arg ARGOS_VERSION=$$VER \
		--build-arg ARGOS_COMMIT=$$COMMIT \
		--build-arg ARGOS_BUILT_AT=$$BUILT \
		-t argos-prod-argos:$$VER \
		-f backend/Dockerfile . && \
	OVERRIDE="$(ARGOS_PROD_DIR)/docker-compose.override.yml"; \
	if [ -f "$$OVERRIDE" ]; then \
		sed -i -E "s|(image: argos-prod-argos:)[^ ]+|\1$$VER|" "$$OVERRIDE"; \
		echo "[build-prod-image] updated $$OVERRIDE -> argos-prod-argos:$$VER"; \
	else \
		echo "[build-prod-image] WARN: $$OVERRIDE not found; image: not patched"; \
	fi

deploy-prod:
	@echo "[deploy-prod] Step 1: sync source to operational dir"
	@ARGOS_PROD_DIR="$(ARGOS_PROD_DIR)" $(SYNC_SCRIPT) --yes
	@echo
	@echo "[deploy-prod] Step 2: build panel image with ldflags injection"
	@$(MAKE) -s build-prod-image
	@echo
	@echo "[deploy-prod] Step 3: docker compose up -d --force-recreate argos"
	@cd "$(ARGOS_PROD_DIR)" && docker compose up -d --force-recreate --no-deps argos
	@echo
	@echo "[deploy-prod] Step 4: verify-deploy"
	@sleep 6 && $(MAKE) -s verify-deploy

verify-deploy:
	@VER=$$(grep -oE 'argosVersion = "[^"]+"' backend/cmd/argos/main.go | head -1 | cut -d'"' -f2); \
	echo "[verify-deploy] expected version=$$VER"; \
	BIN_VER=$$(docker exec argos-prod-panel /argos --help 2>/dev/null | head -1 | awk '{print $$2}'); \
	if [ "$$BIN_VER" = "$$VER" ]; then \
		echo "[verify-deploy] PASS: /argos --help reports v$$BIN_VER"; \
	else \
		echo "[verify-deploy] FAIL: binary reports v$$BIN_VER, expected v$$VER" >&2; \
		exit 1; \
	fi; \
	if [ -n "$$ARGOS_SESSION_TOKEN" ]; then \
		API_VER=$$(curl -sf -H "Cookie: argos_session=$$ARGOS_SESSION_TOKEN" \
			http://localhost:9180/api/system/version 2>/dev/null \
			| grep -oE '"version":"[^"]+"' | cut -d'"' -f4); \
		if [ "$$API_VER" = "$$VER" ]; then \
			echo "[verify-deploy] PASS: /api/system/version reports v$$API_VER"; \
		else \
			echo "[verify-deploy] FAIL: API reports v$$API_VER, expected v$$VER" >&2; \
			exit 1; \
		fi; \
	else \
		echo "[verify-deploy] SKIP: ARGOS_SESSION_TOKEN unset; API surface not verified"; \
	fi

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
