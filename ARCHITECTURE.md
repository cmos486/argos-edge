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

### Fase 4 — WAF (Coraza)
- Build custom de Caddy con `caddy-coraza` (vía xcaddy)
- Toggle de WAF por host
- OWASP CRS cargado, paranoia level configurable
- Editor de exclusiones (el dolor real: tunear falsos positivos)
- Rate limiting por host/path

### Fase 5 — Dashboard de verdad
- Métricas Prometheus de Caddy consumidas por el backend
- Gráficos: tráfico, top hosts, top IPs, 2xx/4xx/5xx
- Vista de ataques bloqueados por WAF
- Tail de access logs en tiempo real (SSE)
- Alertas básicas

### Fase 6 — CrowdSec
- CrowdSec como sidecar en el compose
- Parser de logs de Caddy
- Bouncer integrado (Caddy plugin)
- AppSec opcional
- Vista de decisiones activas en la UI

### Fase 7 — Auth externa (opcional)
- OIDC provider pluggable
- Google, Microsoft, Authelia, etc.
- Mapeo de claims a roles

### Fase 8 — Integraciones
- Webhook a Home Assistant (ataques, bans, certs caducando)
- Export/import de config completa en YAML
- Backup automático de SQLite

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
