# CLAUDE.md

Instrucciones para Claude Code al trabajar en argos-edge.

## Contexto

Este repo es argos-edge, un edge gateway self-hosted (proxy + WAF + LB) construido sobre Caddy. Proyecto de homelab, no comercial. Lee `ARCHITECTURE.md` antes de cualquier cambio estructural.

## Reglas duras

1. **No tocar código fuera del scope pedido.** Si te piden arreglar una función, no refactorices el módulo entero.
2. **ASCII en el código.** Nada de em-dashes, smart quotes, unicode raro en identificadores, comentarios o strings. UTF-8 solo donde sea necesario para i18n.
3. **Sin sobre-ingeniería.** La solución más simple que funcione. No interfaces por si acaso, no capas de abstracción preventivas.
4. **No inventes APIs.** Si no sabes la firma de algo (ej. Caddy Admin API), lee la doc oficial o pregúntame.
5. **Errores explícitos.** `if err != nil { return fmt.Errorf("context: %w", err) }`. Nada de `panic` fuera de `main`.
6. **Commits pequeños y atómicos.** Un cambio lógico por commit. Mensaje en imperativo en inglés: "add host CRUD endpoint", no "added".
7. **No mezcles fases.** Si estamos en Fase 0, no implementes features de Fase 2 "aprovechando".
8. **Si te corrijo, mi corrección manda el resto del chat.**

## Convenciones Go

- `gofmt` siempre. `go vet` sin warnings.
- `golangci-lint` con config por defecto razonable.
- Tests con tabla de casos cuando aplique. No mockear SQLite, usar `:memory:` o archivo temporal.
- Paquetes cortos: `api`, `auth`, `caddy`, `db`. No `argos-backend-api-v1`.
- Errores centinela exportados: `ErrNotFound`, `ErrUnauthorized`. `errors.Is` para comprobar.
- Contextos propagados en todo lo que toque I/O. Timeouts explícitos.
- Logs estructurados con `log/slog`. Niveles: debug, info, warn, error.

## Convenciones frontend

- React 18+, TypeScript estricto, Tailwind para estilos.
- Sin Redux/Zustand en Fase 0. `useState` + contexto si hace falta.
- Fetch con cliente propio en `src/api/client.ts`. Sin react-query/swr hasta que haga falta.
- Componentes en PascalCase, hooks en `useCamelCase`.
- Sin librerías de UI pesadas. Tailwind + headlessui si hace falta accesibilidad.

## Convenciones SQL

- Migraciones numeradas: `001_init.up.sql`, `001_init.down.sql`.
- `snake_case` para tablas y columnas.
- Foreign keys explícitas con `ON DELETE` bien pensado.
- `created_at` y `updated_at` en todas las tablas de entidades, `TIMESTAMP DEFAULT CURRENT_TIMESTAMP`.
- Índices para columnas que se filtren/joinen con frecuencia.

## Seguridad

- Passwords con bcrypt (cost 12 mínimo).
- Session cookies: `HttpOnly`, `Secure`, `SameSite=Lax`.
- CSRF token en mutaciones (Fase 0 puede diferirlo si el panel solo va en LAN).
- Input validation en el servidor, siempre. El frontend valida por UX, no por seguridad.
- Admin API de Caddy NO se expone fuera del network Docker.
- Secretos vía env vars, nunca en código ni DB en claro. Cloudflare API tokens cifrados con AES-GCM usando una master key en env.

## Docker / Deploy

- Multi-stage Dockerfile para backend: build en `golang:alpine`, runtime en `scratch` o `alpine`.
- Frontend se builda con Vite y se copia a `backend/static/` antes del `go build`, para embeberlo.
- `docker-compose.yml` en la raíz. Todo el stack arranca con `docker compose up -d`.
- Volúmenes nombrados, no bind mounts (salvo Caddyfile de bootstrap).

## Antes de cada PR / commit grande

1. `go build ./...` sin errores
2. `go test ./...` en verde
3. `go vet ./...` limpio
4. Frontend: `npm run build` sin warnings
5. `docker compose up -d --build` levanta el stack sin errores
6. Endpoint `/healthz` devuelve 200

## Qué preguntarme antes de actuar

- Cambios en el modelo de datos que rompan migraciones existentes
- Añadir dependencias pesadas (>1MB o con transitivas raras)
- Cambiar decisiones de `ARCHITECTURE.md`
- Exponer nuevos puertos en el compose
- Tocar el Caddyfile de bootstrap (debería ser casi inmutable)
