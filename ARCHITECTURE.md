# argos-edge — Architecture

Self-hosted edge gateway para homelab. Proxy inverso + WAF + load balancing + Let's Encrypt, con panel web unificado. Powered by Caddy + Coraza + CrowdSec.

## Principios de diseño

1. **No reinventar el motor.** Caddy hace proxy/TLS, Coraza hace WAF, CrowdSec hace threat intel. Argos es orquestación + UX por encima.
2. **Opinionado sobre configurable.** Una forma de hacer cada cosa. Defaults sensatos.
3. **Un solo binario + un solo compose.** Nada de 40 servicios.
4. **Config versionable.** Todo exportable a YAML/JSON, importable desde backup.
5. **Stateless panel, stateful proxy.** El panel se puede tirar y levantar sin perder config (Caddy tiene su propio storage de certs).

## Stack

| Capa | Tecnología | Por qué |
|------|-----------|---------|
| Proxy / TLS | Caddy 2 | Let's Encrypt nativo, Cloudflare DNS plugin, Admin API en caliente |
| WAF | Coraza + OWASP CRS | Port Go de ModSecurity, compatible con reglas CRS, plugin nativo para Caddy |
| Threat intel | CrowdSec + AppSec | Community blocklists, bouncer para Caddy, WAF complementario |
| Backend | Go (net/http + chi) | Mismo lenguaje que Caddy/Coraza/CrowdSec, binario estático, concurrencia nativa |
| Storage | SQLite (modernc.org/sqlite) | Suficiente para homelab, Go puro sin CGO, backup = copiar archivo |
| Frontend | React + TypeScript + Tailwind + Vite | Stack conocido, embebido en el binario Go via embed |
| Auth | Local (bcrypt + sessions) | Fase 0. OIDC/OAuth2 pluggable en fase posterior |

## Componentes en runtime

```
                   Internet
                      |
                 [Cloudflare]  (opcional)
                      |
                   :80/:443
                      v
              +---------------+
              |    Caddy      |  <-- Coraza WAF (módulo)
              | (argos-caddy) |  <-- CrowdSec bouncer (módulo)
              +---------------+
                  ^        |
        Admin API |        | reverse_proxy
        :2019     |        v
              +---------------+        +-------------+
              |    Argos      |        |  Upstreams  |
              |    Panel      |        | (LXCs, HA,  |
              | (Go + React)  |        |  NAS, etc)  |
              +---------------+        +-------------+
                      |
                      v
                 [SQLite]
              (hosts, rules,
               users, audit)
```

Caddy vive en su contenedor, expone `:80` y `:443` al mundo y `:2019` (Admin API) solo en la red interna Docker.

El panel Argos se comunica con Caddy por la Admin API para aplicar cambios de config en caliente. No tocamos el Caddyfile después del bootstrap: todo va por API.

## Estructura del repo

```
argos-edge/
├── ARCHITECTURE.md            # Este documento
├── CLAUDE.md                  # Instrucciones para Claude Code
├── README.md
├── LICENSE                    # MIT probablemente
├── .gitignore
├── docker-compose.yml         # Stack completo
├── Caddyfile                  # Bootstrap minimal (luego todo via API)
├── backend/                   # Panel en Go
│   ├── go.mod
│   ├── go.sum
│   ├── Dockerfile
│   ├── cmd/argos/main.go      # Entry point
│   ├── internal/
│   │   ├── api/               # Handlers HTTP (chi router)
│   │   ├── auth/              # Login, sessions, bcrypt
│   │   ├── caddy/             # Cliente Admin API de Caddy
│   │   ├── config/            # Config del panel (env + defaults)
│   │   ├── db/                # SQLite, migraciones
│   │   ├── models/            # Host, Rule, TargetGroup, User, Cert
│   │   └── server/            # HTTP server wiring
│   ├── migrations/            # SQL migrations (goose o similar)
│   └── static/                # Frontend embebido via embed.FS
├── frontend/                  # React
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── tailwind.config.js
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── pages/
│       ├── components/
│       ├── api/               # Cliente del backend
│       └── lib/
└── deploy/
    └── lxc/                   # Scripts/docs para LXC en Proxmox
```

## Modelo de datos (core)

- **User**: id, username, password_hash (bcrypt), created_at, last_login
- **Session**: id, user_id, token, expires_at
- **Host**: id, domain, upstream_url | target_group_id, tls_mode, waf_enabled, created_at
- **TargetGroup**: id, name, algorithm (round_robin/least_conn/ip_hash), sticky, health_check_path, health_check_interval
- **Target**: id, target_group_id, host, port, weight, enabled
- **Rule**: id, host_id, priority, conditions (JSON), action (JSON)
  - Conditions: path_pattern, header_match, method, query_match, remote_ip, geo
  - Actions: forward_to(target), redirect(url), fixed_response(status, body), block, rate_limit(config), challenge
- **Cert**: id, domain, issuer, expires_at, status (gestionado por Caddy, solo read-only mirror)
- **AuditLog**: id, user_id, action, resource_type, resource_id, diff (JSON), timestamp

## Roadmap por fases

### Fase 0 — Plataforma base *(aquí estamos)*
- [x] Estructura de repo
- [ ] `docker-compose.yml` con Caddy + panel Argos arrancando
- [ ] Skeleton backend Go: healthcheck, SQLite + migraciones, servir static embebido
- [ ] Cliente Go para Admin API de Caddy (load/get/update config)
- [ ] Skeleton frontend React: login page, dashboard vacío, routing
- [ ] Auth local (bcrypt + session cookie)
- [ ] User inicial creado por env var o CLI (`argos createuser`)

**Done cuando:** puedes entrar al panel en `http://lxc-ip:8080`, login, y ver un dashboard que muestra "Caddy OK" leyendo el status de la Admin API.

### Fase 1 — Hosts simples
- CRUD de hosts (domain + upstream URL + flag `upstream_verify_tls` para backends self-signed)
- Aplicación via Admin API de Caddy (generar JSON de config, incluyendo `admin.listen` para que el listener se mantenga tras cada `/load`)
- Let's Encrypt automatico via DNS-01 con el proveedor Cloudflare (sin HTTP-01: evita tener que exponer :80 al mundo)
- Vista de certs emitidos (sonda TLS sobre la red Docker contra `caddy:443` con SNI; parsea el leaf)

**Done cuando:** anades `foo.cmos486.es` apuntando a `http://192.168.x.y:8080` desde la UI, y en 30 segundos tienes TLS valido y trafico fluyendo. Para backends con cert self-signed (Home Assistant, Proxmox, Synology), desmarcar `Verify upstream TLS certificate` en el modal aplica `insecure_skip_verify` solo a esa ruta, sin degradar la TLS publica.

### Fase 2 — Target groups obligatorios (AWS-style)
- Todo Host apunta obligatoriamente a un TargetGroup (no mas upstream_url directo)
- El TG posee protocol (http/https), verify_tls, algorithm y toda la config de health check; el Host solo aporta dominio, tls_mode publica y el id del TG
- Targets son plain host+port+weight+enabled dentro del TG
- Algoritmos soportados: round_robin (default), least_conn, ip_hash, random
- Health checks pasivos siempre on con defaults minimos (max_fails=3, fail_duration=30s); activos opt-in con path, method (GET/HEAD/POST), expect_status operator-friendly ("200", "200,301,302", "200-299", "200-204,301"), interval/timeout/fails/passes
- El panel mapea expect_status a la representacion que soporta el JSON de Caddy (codigo exacto, clase 1-5xx, o cae al 0 sin comprobacion cuando el patron cruza clases)
- El modal de Host permite crear inline un TG nuevo con sus targets iniciales, o elegir uno existente
- DELETE de TG devuelve 409 "in use by N hosts" si hay hosts asociados (ON DELETE RESTRICT)
- Migracion 005: up = Go hook (parsea upstream_url de cada host phase-1 y crea TG auto-{domain} con un target); down = SQL que reconstruye upstream_url del primer target enabled y deshace la columna target_group_id
- Sticky sessions se difieren; solo selection_policy por ahora

### Fase 3 — Motor de reglas tipo AWS ALB
- Cada host conserva su `target_group_id` como default action; puede tener N rules que overriden el default cuando matchean
- Rules ordenadas por `priority` (1-50000, incrementos de 10 para permitir insercion sin renumerar), UNIQUE(host_id, priority)
- Matchers soportados (AND dentro de la misma rule; OR = rules separadas con la misma action): `path` (glob Caddy), `path_exact`, `method` (multi), `header` (exact|regex), `query`, `remote_ip` (lista IP/CIDR + toggle negate), `host_header`
- Actions: `forward` (override del TG), `redirect` (301/302/307/308 con placeholders Caddy), `fixed_response` (status 100-599 + body + content_type), `block` (atajo a 403 vacio), `rewrite` (path/strip_prefix/query, cae al default TG tras reescribir)
- Precedencia: Caddy evalua las routes generadas en orden; la primera que matchea es terminal. Un rewrite no reevalua otras rules, siempre pasa al default action del host
- Reorder transaccional via POST /reorder con la lista completa de rule_ids en el orden deseado; el repo park-and-set evita colisiones con UNIQUE a mitad de actualizacion
- UI: `/hosts/{id}/rules` con drag-and-drop (`@dnd-kit/sortable`), modal con builder de matchers + editor de action condicional segun tipo; tabla de hosts añade columna Rules con el count y link directo
- Validaciones servidor: priority en rango, al menos un matcher, method whitelist, header regex compilable, remote_ip parseable, forward TG existente, redirect status en {301,302,307,308}, rewrite con al menos un campo
- Gap de Fase 2 cerrado: `expect_status` rechaza listas que cruzan clases de status (ej. `200,301`) con 400 porque el campo de Caddy solo acepta un int (codigo exacto o clase 1-5xx)

### Fase 3.5 — Log viewer unificado
- Tabla `log_entries` en la propia DB de argos con columnas para `caddy_access`, `caddy_error` y `audit`; retention configurable via `settings` (defaults: 30 dias, 500k filas) + purga cada 6h + VACUUM mensual
- Caddy escribe logs estructurados JSON a `/var/log/caddy/access.log` y `errors.log` (rotacion 100MB x 5 x 7d, permisos 0644 via `mode` en el file writer); volumen `caddy_logs` compartido rw con caddy y ro con argos
- Ingestor en goroutine: `nxadm/tail` con ReOpen sigue rotaciones, parser JSON, batch writer (500 / 2s), seek-to-end al arrancar (lineas durante downtime se pierden del DB pero quedan en disco)
- Recorder de audit: cada handler de mutacion (hosts/TGs/targets/rules/settings) y login/logout emite una entrada `source=audit` via el mismo canal batch
- `host_id` se resuelve desde `host_domain` con cache en el ingestor — Caddy v2 snapshotea `request.headers` al entry y no refleja modificaciones de handlers, asi que el approach header-injection del plan original no funciona. `rule_id` y `upstream` quedan NULL en access logs (limitacion documentada; audit rows cubren rule CRUD)
- API: `/api/logs` con filtros completos (time range, source/host/rule/status expr "4xx"/"500-504"/"200,301", method, path substring o `re:regex`, q free-text), `/api/logs/{id}` detalle, `/api/logs/stream` SSE con heartbeat y cap de 3 conexiones por usuario, `/api/logs/export.csv` (100k filas max), `/api/logs/stats` y `/api/logs/timeseries` con caches de 10s/30s, `/api/logs/presets` hardcoded, `/api/logs/purge` manual
- `/api/settings` con whitelist: solo `logs.retention_days` (1-365) y `logs.max_entries` (10000-5000000); cada PUT se audita
- Frontend: pagina `/logs` con time range, filtros, stats cards, tabla coloreada por status class, drawer lateral con raw JSON + Trace similar, Live toggle con EventSource, presets dropdown, export CSV. `/settings` con seccion Logs (retention + max_entries + purge now). Hosts table gana shortcut "View logs" pre-filtrando por `host_id`

### Fase 4 — WAF + Rate limiting
- Build custom de Caddy via xcaddy pineado a versiones upstream:
  coraza-caddy/v2 v2.5.0, caddy-ratelimit v0.1.0, coreruleset v4.25.0 LTS
- Por host, tres superficies:
  1. WAF Coraza + OWASP CRS (`host_security.waf_enabled` + mode detect|block + paranoia 1-4)
  2. Rate limit (`host_security.rate_limit_*` con key ip|header|global y ventana 1-3600s)
  3. Rules CRUD y default TG por debajo
- Orden de handlers por host: un outer route con handle = [rate_limit?, waf?, subroute(rule routes + default)], todos evaluados terminal. El subroute preserva el first-match-wins de Fase 3
- Exclusions (tabla `waf_exclusions`): por CRS rule id, globales o con `path_pattern` para scope. UNIQUE(host, rule, path) enforced con path NOT NULL DEFAULT '' para que el "una global por host+rule" funcione sin trucos SQL
- Custom SecRule (`waf_custom_rules`): texto raw validado a nivel sintactico + id en 100000-899999. Banner "advanced" en UI
- Coraza audit log: `/var/log/caddy/waf-audit.log` JSON serial con parts ABIJDEFHKZ (K es el matched-rule list, sin K no se captura nada); el ingestor fan-out a una fila por rule matcheada con waf_rule_id + waf_severity (CRITICAL/ERROR/WARNING/NOTICE/INFO mapeados desde los ints 0-6 de ModSecurity)
- Directivas SecDefaultAction quedan fuera de la base de argos porque Coraza v3 ya las inicializa; redefinirlas rompe el parse
- Catalog de 498 rules CRS v4.25.0 parseado al arranque desde /etc/coraza/crs/rules/*.conf para autocomplete en la UI
- Fix del gap de Fase 3.5: host con TG sin targets enabled ya no se omite; emite un static_response 503 catch-all (WAF sigue evaluando en ese path)
- Limitacion documentada: `waf_block_status` del DB no siempre se aplica — Coraza por defecto devuelve 403 en block; para custom status hay que emitir una custom SecRule con `deny,status:N`

### Fase 5 — Notificaciones y alertas
- Cuatro canales pluggables: webhook (net/http), email SMTP (wneessen/go-mail v0.7.2 con PLAIN/LOGIN + STARTTLS/TLS), telegram (Bot API via net/http), browser_push (SherClockHolmes/webpush-go v1.4.0 con VAPID generado al arranque)
- Diez event types hardcoded: cert_expiring_soon, cert_renewal_failed, waf_attack_burst, target_unhealthy, target_recovered, waf_detect_mode_reminder, config_change, rate_limit_triggered, login_failed, health_degraded
- Reglas: event_type + filtros (host_ids, severities) + throttle per-(rule,event,host) con ventana configurable
- Worker goroutine drena cola bufferada (cap 1000) con retry exponencial (hasta 3 intentos, 2^n segundos + jitter) y rate-limit token-bucket por canal
- Secretos (smtp_password, bot_token, webhook.headers, VAPID private) cifrados con AES-GCM via ARGOS_MASTER_KEY (32 bytes hex); sentinel UNCHANGED en PUT preserva ciphertext previo
- Observer callback del ingestor alimenta sliding windows in-memory (ataques WAF por remote_ip, 429 bursts por host, transiciones target up/down via logger de health_checker)
- Cron diario para cert_expiring_soon (<14d) y waf_detect_mode_reminder (>7d); cron de 30s para /healthz + caddy admin (health_degraded)
- Panel: /notifications con 4 tabs (Channels, Rules, History, My Devices); dashboard gana widget Recent alerts (últimas 5 deliveries severity critical/error en 24h)
- Service worker /push-sw.js registra el navegador como endpoint; UI marca HTTPS-required cuando isSecureContext=false (funcionará en Fase 9 cuando el panel vaya detrás de Caddy)
- Retención: cron horario purga por edad (notifications.retention_days) y por tamaño (notifications.max_entries)
- Limitaciones documentadas: el LogWatcher reinicia sus sliding windows al reiniciar el panel (in-memory); rotación del master key no automatizada (requiere re-crear canales)

### Fase 6 — Dashboard de verdad (shipped)
- Tres endpoints de agregación + uno de salud bajo `/api/dashboard/*`:
  - `GET /overview` -- totales 24h (requests, blocked=403+429, errors 5xx), hosts activos, targets deshabilitados, certs <14d, último backup
  - `GET /traffic?range=1h|6h|24h|7d&host_id=N` -- timeseries por clase de status, percentiles p50/p95/p99 de duration_ms, top 10 hosts, top 20 paths, bandwidth
  - `GET /security?range=...` -- timeseries detected vs blocked, top 10 rule_ids, top 20 IPs (count, distinct hosts, last_seen), top 10 paths, rate_limit_hits
  - `GET /health` -- estado por TG, lista de certs ordenada por days_left, último backup, uptime panel, Caddy probe, últimos 10 errores
- Queries SQL directas contra `log_entries` (sin rollup table), con índice compuesto por columna relevante ya existente desde las fases 3.5 y 4. Bucketing hecho en Go (no en SQL via `strftime`) porque el driver modernc.org/sqlite serialisa `time.Time` en un formato que `strftime` no parsea
- Percentiles: fetch ordenado + `sort.Ints` + nearest-rank en Go; con buckets de pocas filas el p95 colapsa al máximo, asumido como limitación de baja-volumetría
- Cache in-memory con TTL 30s por clave `endpoint+range+host_id`; primera llamada ~30ms, subsiguientes ~5ms. Invalida lazy por expiración
- Frontend `/dashboard` rediseñado: 4 secciones verticales (Overview, Traffic, Security, Health) con charts de `recharts@3.8.1` (AreaChart apilado por status class y detected-vs-blocked, LineChart para percentiles). Auto-refresh cada 30s con toggle "pause" e indicador "updated Xs ago"; rangos de Traffic y Security independientes; `ErrorBoundary` por sección
- Limitaciones: (1) sin geolocation de IPs (diferido a Fase 10); (2) el recuento de certs hace SNI-probe vivo en paralelo contra caddy:443 -- primera llamada fria del Overview puede costar ~200ms si hay muchos hosts, pero la cache de 30s absorbe clicks repetidos; (3) recharts infla el bundle frontend de ~380KB a ~760KB minified (~215KB gzip); aceptable para homelab, candidato a dynamic import si crece

### Fase 7 — CrowdSec
- CrowdSec como sidecar en el compose
- Parser de logs de Caddy
- Bouncer integrado (Caddy plugin)
- AppSec opcional
- Vista de decisiones activas en la UI

### Fase 8 — Auth externa (opcional)
- OIDC provider pluggable
- Google, Microsoft, Authelia, etc.
- Mapeo de claims a roles

### Fase 9a — Backup/Restore + Export/Import (shipped)
- Backups locales en volumen dedicado `argos_backups` montado en `/data/backups` dentro del contenedor. Sin rclone ni S3 en esta fase (posible futuro)
- `VACUUM INTO` produce un snapshot consistente de `argos.db` sin bloquear escrituras en curso; la tabla `backups` registra filename UNIQUE + sha256 + size + kind (manual/scheduled) + trigger_user_id + note
- Tar.gz empaqueta argos.db + metadata.json + best-effort lectura RO de `caddy_data` montado en `/data/caddy` (archivos inaccesibles por permisos se omiten sin abortar). Restore SOLO reemplaza argos.db; Caddy vuelve a emitir certs via ACME DNS-01
- Scheduler con `robfig/cron/v3` v3.0.1 lee `backup.schedule` al arrancar (hot-reload fuera de scope, requiere restart). Cada ejecución emite `backup_completed` / `backup_failed` y corre retención por edad y conserva siempre el más nuevo
- Flujo de restart tras restore: el handler escribe `/data/.restore_pending` + path del tar extraído, responde 202, hace flush, y 800ms después llama `os.Exit(0)`. Docker `restart: unless-stopped` vuelve a arrancar el contenedor; `main.go` invoca `backup.ApplyPending` ANTES de abrir el pool de SQLite, mueve el argos.db restaurado al path vivo, limpia el flag y emite `config_restored`
- CLI: `docker compose exec argos /argos restore --file /data/backups/X.tar.gz --yes` escribe el flag y sale 0; el operador hace `docker compose restart argos` manualmente
- `configio` Export YAML: snapshot portable de hosts + TGs + rules + host_security (con exclusions y custom rules embebidas) + notification_channels (secretos reemplazados por literal `__REDACTED__`) + notification_rules + settings whitelisted (sin VAPID, sin CF token). Header informativo con timestamp y nota de redacción
- Import YAML con dos modos:
  1. `merge`: upsert por clave natural (host.domain, tg.name, channel.name, rule.name); si un canal existe y el YAML trae `__REDACTED__`, se preserva el ciphertext previo
  2. `replace`: DELETE completo en orden de FKs seguido de INSERT; canales con secretos redacted quedan con string vacío + `enabled=false` + warning explícito
  Todo en una `*sql.Tx` -- rollback total si cualquier INSERT falla
- UI `/backup` con 3 tabs (Backups / Export-Import / Settings); widget "Last backup" en Dashboard con badge `stale` si >48h sin backup exitoso; cortina fullscreen "Argos is restoring" mientras el contenedor reinicia (reload automático a los 18s)
- Tres nuevos event types en el catálogo: `backup_completed`, `backup_failed`, `config_restored`
- Limitaciones documentadas: (1) rotación de ARGOS_MASTER_KEY no automatizada; (2) cambiar `backup.schedule` requiere restart del contenedor
- Polish v0.7.1: `Manager.Reconcile(ctx)` corre en cada arranque (tras abrir la DB, antes del scheduler). Escanea `/data/backups/*.tar.gz` y sincroniza en ambos sentidos: archivos sin row se insertan (kind=manual/scheduled si el `metadata.json` embebido es parseable, si no kind=orphan con nota "recovered during reconcile"); rows sin archivo se eliminan con log INFO. Migración 012 expande el CHECK de `backups.kind` para aceptar 'orphan'. Cierra el gap de la Fase 9a donde un restore dejaba tar.gz huérfanos fuera de la tabla
- Polish v0.7.1: `metadata.contents.caddy_files` ahora refleja el número real de archivos escritos al tar (antes contaba el walk, incluyendo ceros denegados por permisos). `writeArchive` serializa argos.db primero, luego recorre caddy contando solo los `Write` exitosos, y escribe `metadata.json` AL FINAL con el count real

### Fase 9b — Hardening operacional (shipped)
- Panel mode configurable: `ARGOS_PANEL_MODE` = `lan` (default) o `behind_caddy`
  - **lan**: HTTP en `0.0.0.0:8080`, cookies `HttpOnly; SameSite=Strict` (no Secure), sin HSTS/CSP. `:8080` publicado en el host. Accesible en `http://<lan-ip>:8080`
  - **behind_caddy**: requiere `ARGOS_PANEL_DOMAIN`. Cookies `Secure+SameSite=Strict`, añade `Strict-Transport-Security: max-age=31536000; includeSubDomains` y una CSP estricta (`default-src 'self'`, `frame-ancestors 'none'`, `form-action 'self'`). `:8080` NO se publica; Caddy accede al panel por el bridge interno via service name `argos:8080`. Bootstrap automático al primer arranque: inserta una fila `hosts` + TG `argos-panel-internal` (target `argos:8080`) para que Caddy emita TLS ACME inmediatamente
- Breaking change: se elimina `ARGOS_COOKIE_SECURE` (fase 0). El flag Secure ahora se deriva de `ARGOS_PANEL_MODE`
- Compose layering: `docker-compose.yml` (LAN default) + `docker-compose.behind-caddy.yml` que usa `!reset []` sobre `ports` para des-publicar `:8080`. Requiere Compose v2.24+. Comando:
  `docker compose -f docker-compose.yml -f docker-compose.behind-caddy.yml up -d`
- Security headers middleware (baseline en ambos modos): `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` neutralizando sensores/cámaras. CSP + HSTS solo en `behind_caddy`
- Session timeouts configurables via settings (`session.absolute_timeout_hours`, `session.idle_timeout_hours`; defaults 168/24) con cache 1 min en memoria. Nueva columna `sessions.last_seen_at`; middleware `Authenticate` enforza ambos límites y llama a `Touch` con throttle de 5 min para evitar una escritura por request
- Login rate limit: 5 fallos en 5 min desde la misma IP → ban de 30 min. Cada intento se persiste en tabla `login_attempts` (purgada a las 24h desde el cron de logs). Cache in-memory corta el path rápido sin query. Respuesta 429 con `Retry-After` en segundos. Auditoría via `rate_limited_login`
- `/api/system/health`: `runtime.MemStats` (alloc/sys/num_gc), goroutines, SQLite pool stats + tamaños DB/WAL, profundidad de la cola de notificaciones, último backup, uptime del panel, `panel_mode` + `panel_domain`. Sin cache (datos cambian rápido, query light)
- Docker-compose: `restart: unless-stopped` en ambos servicios; `mem_limit` + `cpus` vía env (`ARGOS_MEM_LIMIT` 512m, `ARGOS_CPU_LIMIT` 1.0, `CADDY_MEM_LIMIT` 256m, `CADDY_CPU_LIMIT` 0.5)
- Frontend: nueva página `/system` con cards de Memory/Runtime/SQLite/Workers/Scheduler (auto-refresh 10s + pause toggle). Nuevo tab Security en `/settings` para editar timeouts. Banner persistente en header si `panel_mode=lan` y el browser no está en localhost. My Devices de `/notifications` muestra explicación clara de HTTPS-required cuando mode=lan
- Limitaciones documentadas:
  1. **CSP `unsafe-inline`** en `script-src` y `style-src` -- recharts y Tailwind runtime inyectan estilos inline; migrar a nonces queda diferido
  2. **LAN banner** se oculta cuando el host es localhost/127.0.0.1 porque es confuso mostrarlo en dev; no depende de la mode real del panel
  3. **2FA, OIDC y ACLs por rol** siguen fuera de scope (Fases 8 / 10)
  4. **`docker kill`** no dispara el `restart: unless-stopped`: Docker trata el kill via API como "stop manual". Un crash real del proceso (SIGKILL al PID del proceso) sí lo activa
  5. La **rotación de `ARGOS_MASTER_KEY`** sigue siendo manual, sin cambios respecto a fase 5/9a

### Fase 9c — Integraciones remotas (pendiente)
- Webhook a Home Assistant (gran parte cubierto por Fase 5; queda la integración opinionada con HA API)
- rclone / S3 como destino de backup (`backup.rclone_remote`)

## Decisiones técnicas importantes

**Caddy como proceso separado, no embebido.**
Más limpio para actualizaciones, hot reload, y separación de fallos. El panel puede crashear y el proxy sigue sirviendo tráfico.

**Config 100% via Admin API tras bootstrap.**
El Caddyfile inicial es minimal. Todo lo demás se aplica por JSON a `/load` o endpoints específicos. Esto permite cambios atómicos sin downtime.

**SQLite con WAL mode.**
Suficiente para un homelab. Si alguien necesita más, puede migrar a Postgres en el futuro; la capa de persistencia está tras una interfaz.

**Frontend embebido en el binario Go.**
`embed.FS` para servir los estáticos del build de Vite. Un solo binario = un solo Dockerfile trivial.

**Sin CGO.**
`modernc.org/sqlite` permite SQLite puro Go. Binario estático, cross-compile trivial, Dockerfile `FROM scratch`.

**Sesiones, no JWT.**
Cookie httponly + secure, sesión en SQLite. Revocable instantáneo, más simple. JWT no aporta nada en un panel single-node.

## No-goals (por ahora)

- Multi-tenancy
- Clustering / HA del panel
- Exponer el panel a internet sin estar detrás del propio Caddy (dogfooding en Fase 1+)
- Kubernetes / CRDs
- Soporte nginx/Traefik (solo Caddy)
