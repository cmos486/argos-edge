# CLAUDE.md

Instrucciones para Claude Code al trabajar en argos-edge.
Onboarding doc: lee este archivo antes de cualquier cambio
significativo.

## Contexto

Self-hosted edge gateway para homelabs (proxy + WAF + LB + SSO)
construido sobre Caddy 2 + CrowdSec + Coraza/CRS. Go backend,
React + TypeScript + Tailwind frontend embebido en el binario.
SQLite como storage. **Estado actual: v1.3.36.8 estable**
(panel binary `1.3.35`; v1.3.34/v1.3.35/v1.3.36.x son
tooling/demo/capture-automation patches). Proyecto
solo-maintainer; homelab-grade, no cloud-scale.

Lee primero:

- `docs/architecture/components.md` — qué containers existen y
  cómo se hablan (con diagramas mermaid)
- `docs/architecture/storage.md` — SQLite + migraciones + tabla
  catalog (highest migration: 033, schema-frozen since v1.3.33)
- `docs/architecture/request-flow.md` — qué hace cada hop
- `CHANGELOG.md` — historial release-by-release
- `docs/operations/verification-report.md` — matriz feature →
  smoke

## Reglas duras

1. **No tocar código fuera del scope pedido.** Si te piden
   arreglar una función, no refactorices el módulo entero.
2. **ASCII en el código.** Nada de em-dashes, smart quotes,
   unicode raro en identificadores, comentarios o strings. UTF-8
   solo donde sea necesario para i18n.
3. **Sin sobre-ingeniería.** La solución más simple que funcione.
   No interfaces por si acaso, no capas de abstracción
   preventivas.
4. **No inventes APIs.** Si no sabes la firma de algo (ej. Caddy
   Admin API, CrowdSec LAPI, Caddy plugin internals), lee la doc
   oficial o el código upstream antes de escribir cliente. Ver
   "Eleven-strike pattern" abajo — pre-implementation verification
   beats mid-implementation discovery cada vez.
5. **Errores explícitos.** `if err != nil { return
   fmt.Errorf("context: %w", err) }`. Nada de `panic` fuera de
   `main`.
6. **Commits pequeños y atómicos.** Un cambio lógico por commit.
   Mensaje en imperativo en inglés: "add host CRUD endpoint", no
   "added". Author `cmos486` (operator's git config email; full
   value lives in `feedback_commit_format.md`, not inline here so
   `scripts/check-no-personal-data.sh` stays green). **NO
   `Co-Authored-By:` trailers. NO `Generated-with:` markers. NO
   `Signed-off-by:` trailers.** Single-maintainer project;
   co-authorship to a model is misleading. Pre-push verification:
   `git show -s --format=%B <sha> | grep -cE '^Co-Authored-By:'`
   debe devolver `0` (regex anchored a line-start para no
   false-positive en prose que cita el trailer literalmente).
7. **Smoke real before tagging.** Para cualquier release que
   toca CrowdSec / Caddy / runtime behavior: el smoke EFFECT en
   `scripts/smoke/` corre contra el live stack y pasa antes de
   `git tag`. Unit tests prueban emit; smoke prueba effect. No
   son intercambiables.
8. **STOP+REPORT pattern.** Cuando descubras algo upstream-
   diferente-de-docs mid-implementation, no improvises. STOP,
   REPORT con findings, await operator decision. La sesión
   actual sigue las correcciones del operador para el resto del
   chat.
9. **Si te corrijo, mi corrección manda el resto del chat.**

## Working agreement (memorized)

Heredado de v1.3.20+ después de varios incidentes:

- **Smoke verifies EFFECT, not specs.** Un smoke que solo asserta
  shape de respuesta es inútil contra upstream-narrower-than-docs.
  Siempre asserta state-change real (decision count, panel state,
  on-disk file content).
- **Dual-dir deploy gap discipline.** El operator usa un patrón
  `~/argos-edge/` (git checkout) + `~/argos-prod/` (compose
  operacional) con bind-mounts crowdsec/* viviendo en argos-prod.
  Antes de cualquier smoke: `make sync-prod-dry` para verificar
  que el repo y el operacional están en sync. `make sync-prod`
  aplica.
- **Bind-mount inode invalidation.** rsync replaces files via
  tempfile+rename (cambia inode). Docker bind mounts pin el inode
  al startup. Después de `make sync-prod` de un script bind-
  mounted (setup-appsec.sh, Caddyfile, crowdsec/*),
  `docker compose restart <service>` es obligatorio para que el
  container vea el nuevo archivo.

## Eleven-strike upstream-behaviour pattern

Histórico de 11 incidentes a través de v1.3.18-v1.3.34.3
donde tests con fakes pasaron pero el upstream real
(CrowdSec LAPI, caddy plugin, docker bind mounts,
alert-shape cap, deploy-infrastructure silent rebuild) era
más narrow o se comportaba diferente que la doc oficial
sugería. El strike más reciente (v1.3.34.3) fue un
deploy-pipeline gap: `build: !reset` + image pin convirtieron
`make deploy-prod` en un silent no-op; v1.3.34.1+v1.3.34.2
shipped código que jamás se desplegó. Casos completos en
`~/.claude/projects/-home-claude-argos-edge/memory/project_four_strike_upstream_pattern.md`
(filename retained for git-history continuity).

Lección operativa: cualquier release que toque LAPI/Caddy
plugin/external protocol layers hace pre-implementation check
(<30 min) ANTES de escribir client code:

- `curl` el endpoint asumido contra el live LAPI
- `grep` el upstream source para la registración de la ruta
- Para Caddy plugins: lee el handler/app struct en el tag
  pinneado Y en main; las json/caddyfile tags
- Si el surface no existe / es diferente: STOP+REPORT antes de
  escribir client code

## Patterns memorizados (v1.3.30-v1.3.36)

### Reverse-sentinel pattern (v1.3.30)

Para surfacing 0600 root-owned crowdsec_config state al panel
(que corre como nobody): setup-appsec.sh (root inside crowdsec)
escribe `/shared/argos-<thing>.json` (default umask 0644,
panel-readable). Panel lee con mtime-based cache invalidation.
Inverso del v1.3.19+ pattern original (panel writes, script
consumes). Detalle:
`memory/project_reverse_sentinel_pattern.md`. Implementación de
referencia:
`backend/internal/security/scenarios/descriptions.go`.

### Async-job pattern (v1.3.31)

Para operaciones long-running que necesitan progress feedback +
boot-time recovery + single-worker safety:

- Tabla `<thing>_jobs` con state enum
  (pending|running|completed|failed)
- Worker goroutine bound al panel main-context (sobrevive el
  202 response)
- Single-worker mutex serializa concurrent submits (queue
  automático via state=pending)
- Boot-time recovery transiciona pending+running →
  failed/'panel restarted'
- Polling endpoint `GET /api/security/jobs/{id}`

Implementación de referencia:
`backend/internal/security/country/jobs.go`. Detalle:
`memory/project_async_job_pattern.md`.

### Reconciler pattern (v1.3.27, v1.3.33)

Periodic ticker compara panel intent vs actual upstream state,
flips `state='drifted'` cuando divergen. Ej.: drift detector
para scenarios + tuning (60s tick); country reconciler para
expansion divergence (5min tick). Implementaciones:
`backend/internal/security/drift/drift.go`,
`backend/internal/security/country/reconciler.go`.

## CAPI shape lesson (v1.3.33)

Cuando emites bulk LAPI data (scope=Range bans, etc.):
**mirror la shape de CAPI/community-blocklist** — 1 alerta con
N decisions inside `decisions[]`, NO N alertas con 1 decision
cada una. La shape per-CIDR colisiona con
`flush.max_items: 5000` default y dispara cascade flush
silencioso. La community-blocklist shape es la única probada
upstream a scale.

Implementación de referencia (post-fix):
`backend/internal/crowdsec/client.go::AddRangeDecisions`.

## Convenciones Go

- `gofmt` siempre. `go vet` sin warnings.
- `golangci-lint` con config por defecto razonable.
- Tests con tabla de casos cuando aplique. SQLite tests usan
  `:memory:` con `db.SetMaxOpenConns(1)` (cada conn ve su propio
  in-memory DB; sin el cap, tests con goroutines escribiendo en
  paralelo ven "no such table").
- Paquetes cortos: `api`, `auth`, `caddy`, `db`. No
  `argos-backend-api-v1`.
- Errores centinela exportados: `ErrNotFound`, `ErrUnauthorized`.
  `errors.Is` para comprobar.
- Contextos propagados en todo lo que toque I/O. Timeouts
  explícitos.
- Logs estructurados con `log/slog`. Niveles: debug, info, warn,
  error.

## Convenciones frontend

- React 18+, TypeScript estricto, Tailwind para estilos.
- Sin Redux/Zustand. `useState` + contexto si hace falta. State
  fetching directo via `src/api/client.ts`. Sin
  react-query/swr (el panel maneja staleness con poll loops o
  manual refresh; complejidad innecesaria).
- Componentes en PascalCase, hooks en `useCamelCase`.
- Sin librerías de UI pesadas. Tailwind + headlessui si hace
  falta accesibilidad.

## Convenciones SQL

- Migraciones numeradas: `001_init.up.sql`, `001_init.down.sql`.
  Estado actual: 30 archivos hasta migration 033
  (v1.3.33 = última que tocó schema; v1.3.34+ son
  tooling/doc-only sin schema changes).
- `snake_case` para tablas y columnas.
- Foreign keys explícitas con `ON DELETE` bien pensado.
- `created_at` y `updated_at` en todas las tablas de entidades,
  `TIMESTAMP DEFAULT CURRENT_TIMESTAMP`.
- Índices para columnas que se filtren/joinen con frecuencia.
- Idempotent up + down. La rollback test pin
  (`TestRollbackLastMigration` en `internal/db/migrate_test.go`)
  asserta que cada migración se puede rollback limpiamente; al
  añadir migración N, extiende el peel chain ahí.

## Seguridad

- Passwords con bcrypt (cost 12 mínimo).
- Session cookies: `HttpOnly`, `Secure`, `SameSite=Lax` (`Strict`
  en `behind_caddy` mode).
- CSRF token en mutaciones — el panel usa session cookies +
  same-site protection.
- Input validation en el servidor, siempre. El frontend valida
  por UX, no por seguridad.
- Admin API de Caddy NO se expone fuera del network Docker.
- Secretos vía env vars, nunca en código ni DB en claro.
  Cloudflare API tokens + OIDC client secrets + SMTP / Telegram
  / Push secrets cifrados con AES-GCM usando `ARGOS_MASTER_KEY`.
- **Sanitization pre-public**: `scripts/check-no-personal-data.sh`
  catch operator-specific data en docs committed. Use
  RFC 5737 IPs (192.0.2.x, 198.51.100.x, 203.0.113.x) y
  `example.com` para placeholders. NO operator-specific
  domains/IPs/usernames en archivos committed.

## Docker / Deploy

- Multi-stage Dockerfile para backend: build en `golang:alpine`,
  runtime en `scratch` o `alpine`. Frontend builda con Vite y
  copia a `backend/static/` antes del `go build` para embeber.
- `docker-compose.yml` en la raíz. Stack arranca con
  `docker compose up -d`.
- Volúmenes nombrados, no bind mounts (salvo bootstrap files
  + `crowdsec/*` que sí son bind-mounted desde la repo para
  permitir hot-reload de scripts via `make sync-prod` +
  container restart).
- Operator tooling: `Makefile` con `sync-prod`, `sync-prod-dry`,
  `deploy-prod`, `verify-prod`, `smoke-self`. Detalles en
  `docs/operations/deployment.md`.

## Smoke suite (`scripts/smoke/`)

18 smoke scripts cubren el verification matrix completo
(`docs/operations/verification-report.md`). Cada uno tiene
header con: qué feature testa, EFFECT verificado, env vars
requeridas, exit codes. Importantes:

- `sync-prod.sh` — operator-tooling self-smoke (no auth)
- `lapi-wal.sh` — WAL mode active + warning ausente
- `scenario-descriptions.sh` — v1.3.30 reverse-sentinel
  EFFECT (slimmed scenarios index, mtime cache)
- `scenarios-toggle.sh` + `appsec-tuning.sh` — v1.3.25 sentinel
  flow
- `drift-detection.sh` — v1.3.27 60s reconciler EFFECT
- `true-detect-mode.sh` — v1.3.29 profiles.yaml splice EFFECT
  (sintético LAPI POST porque inband AppSec no genera LAPI
  decisions)
- `country-expansion-async.sh` — v1.3.31 submit+poll+complete
  (refuse-to-run con placeholder defaults; v1.3.33 isolation
  gate)
- `country-reconciler.sh` — v1.3.33 5min reconciler EFFECT
  (expansion-divergence detection)
- `lapi-flush-cap.sh` — v1.3.33 alert-shape verification (NG
  +1 chunk + IR +3 chunks; no flush cascade)
- `host-crud.sh` + `whitelist-roundtrip.sh` +
  `banned-ips-roundtrip.sh` — v1.3.32 verification gap fillers
- `deploy-rebuild.sh` — v1.3.34.3 deploy-pipeline EFFECT
  (image rebuild after make deploy-prod, post 11-strike #11)
- `demo-environment.sh` — v1.3.35 demo-stack self-smoke
- `capture-automation.sh` — v1.3.36.x Playwright capture
  spec self-smoke (storageState wiring, safeClick blocklist,
  per-surface selectors)
- `auth-flow.sh` — operator-credential gated; runs manually

## Antes de cada PR / commit grande

1. `go build ./...` sin errores
2. `go test ./...` en verde
3. `go vet ./...` limpio
4. Frontend: `npm run build` sin warnings
5. `docker compose up -d --build` levanta el stack sin errores
6. Endpoint `/healthz` devuelve 200
7. `mkdocs build --strict` clean (si docs cambiaron)
8. `./scripts/check-no-personal-data.sh` clean (siempre)
9. Smoke EFFECT del feature touched corre PASS contra prod stack

## Qué preguntarme antes de actuar

- Cambios en el modelo de datos que rompan migraciones existentes
- Añadir dependencias pesadas (>1MB o con transitivas raras)
- Cambiar decisiones arquitectónicas documentadas en
  `docs/architecture/`
- Exponer nuevos puertos en el compose
- Tocar el Caddyfile de bootstrap (debería ser casi inmutable)
- Cualquier cambio que toque el upstream surface (LAPI, Caddy
  plugin, AppSec) — pre-flight verification mandatory antes de
  client code

## Memoria persistente

Este CLAUDE.md es la documentación human-facing checked-in. La
memoria session-persistent del Claude Code agent vive en
`~/.claude/projects/-home-claude-argos-edge/memory/`:

- `MEMORY.md` — index
- `project_four_strike_upstream_pattern.md` — los 11 strikes
  completos (filename retained for git-history continuity)
- `project_reverse_sentinel_pattern.md` — pattern detail
- `project_async_job_pattern.md` — pattern detail
- `project_dual_dir_deploy_gap.md` — el dual-dir gap
- `project_v1325_scenarios_source_of_truth.md` — filesystem
  mount approach
- ... más entries por feature/incident
- `feedback_*.md` — operator preferences acumuladas

Future Claude sessions: este CLAUDE.md es onboarding rápido;
los memory files son el detalle. No dupliques contenido entre
los dos — link de aquí a memory cuando profundices.
