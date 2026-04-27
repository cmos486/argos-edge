# Deployment

argos-edge is shipped as a `docker compose` stack. The simplest
deployment is a single git checkout where `docker compose up -d`
runs from the same directory `git pull` does. v1.3.26 also
supports a "dual-dir" pattern: a separate operational directory
that holds the operator's prod-specific overrides and runs
`docker compose`, while the source-of-truth git checkout lives
elsewhere on the host.

The dual-dir pattern motivated this page. v1.3.25 prod-smoke
caught a real failure mode where the panel image and the compose
volume mount were both at the new release, but bind-mounted
files (`crowdsec/setup-appsec.sh`, `Caddyfile`) were stuck at a
prior version because nobody had synced them from the source
checkout into the operational dir. v1.3.26 ships
`scripts/sync-prod.sh` + `make deploy-prod` to make that gap
impossible to forget.

## Single-dir deployment (the simple case)

This is what `docs/release-notes/*.md` upgrade sections assume:

```bash
cd /path/to/argos-edge
git pull
docker compose build
docker compose up -d
```

`docker compose` reads the `docker-compose.yml` from the current
directory and resolves bind-mount paths (`./crowdsec/setup-
appsec.sh`, `./Caddyfile`) relative to it. Since `git pull` and
`docker compose` run in the same dir, every release lands
atomically.

If this is your setup, you do not need the `make` targets below.

## Dual-dir deployment (the homelab pattern)

Some operators keep the git checkout separate from the
operational dir:

- `~/argos-edge/` -- where `git pull` happens. Source of truth.
- `~/argos-prod/` -- where `docker compose` runs. Holds the
  operator's `.env`, `docker-compose.override.yml` (image pin
  + ports + container names), and the `argos.db` volume mount
  state.

Why split them: the operator wants to keep operational secrets
(.env, override file) outside any directory subject to a `git
clean -fd` or a fresh `git clone`. Or run multiple stacks
(prod + staging) off one checkout.

The hazard: bind-mount paths in `docker-compose.yml` resolve
relative to where `docker compose` runs from. The operational
dir's copy of `crowdsec/*` and `Caddyfile` is what the
containers see at runtime, regardless of what the source
checkout says. Without an explicit sync step, a release that
touches `setup-appsec.sh` is invisible to the running stack.

### Sync via Makefile

The Makefile in the source checkout root provides the
operator-facing targets:

```bash
cd ~/argos-edge

# Preview what would change. No writes.
make sync-prod-dry

# Sync source -> operational dir. Interactive confirm.
make sync-prod

# Build a fresh panel image with build-time version metadata
# (argosVersion + git short-hash + ISO timestamp injected via
# ldflags) and rewrite the override.yml image: line.
make build-prod-image

# One-command upgrade path:
#   sync (auto-confirm) + build-prod-image + force-recreate +
#   verify-deploy.
make deploy-prod

# Assert the deployed binary version matches argosVersion in
# main.go. Reads /argos --help; if ARGOS_SESSION_TOKEN is set,
# also hits /api/system/version. PASS / FAIL exit code.
make verify-deploy

# Self-smoke for sync-prod itself (runs against tmpdirs):
make smoke-self
```

#### The explicit-retag flow (v1.3.34.3+)

`docker-compose.override.yml` in `~/argos-prod` keeps a hard pin:

```yaml
services:
  argos:
    image: argos-prod-argos:v1.3.34.3
    build: !reset
```

`build: !reset` deliberately disables `docker compose build`
for the argos service in the prod project. Without this guard,
a stray `docker compose up --build` would silently retag the
image at the same tag, producing a moving target where
"argos-prod-argos:v1.3.34.3" could mean any of N different
binaries depending on when the operator last ran build.

`make build-prod-image` is the only sanctioned way to produce
a new panel image:

1. Reads `argosVersion` from `backend/cmd/argos/main.go` (the
   single source of truth for the version string).
2. Resolves `git rev-parse --short HEAD` and the current UTC
   timestamp.
3. Runs `docker build` with the three values passed as
   `--build-arg`s; the Dockerfile's ldflags step injects them
   via `-X main.argosVersion=...` etc., overriding the
   source-tree fallback in `main.go`.
4. Tags the image as `argos-prod-argos:<argosVersion>`.
5. `sed`-rewrites the `image:` line in
   `docker-compose.override.yml` to point at the new tag.

`make deploy-prod` chains `sync-prod` (--yes) → `build-prod-image`
→ `docker compose up -d --force-recreate` → `verify-deploy`. The
final verify step asserts the version match, so a botched build
exits the deploy with a clear FAIL line instead of silently
re-using the old image.

**The `make build-prod-image` step replaces the pre-v1.3.34.3
silent `docker compose build` no-op.** Two prior fix releases
(v1.3.34.1 + v1.3.34.2) shipped under that hidden gap and
required manual `docker build` + override-edit recovery (see
the v1.3.34.2 release notes for the incident timeline).

`ARGOS_PROD_DIR` overrides the default `~/argos-prod`:

```bash
ARGOS_PROD_DIR=/srv/argos-prod make deploy-prod
```

### What sync-prod copies and what it protects

`scripts/sync-prod.sh` mirrors the source repo into the
operational dir using `rsync -a --delete`, with explicit
exclusions for files that are operator-managed or
build-generated. The denylist:

| Excluded | Why |
|---|---|
| `docker-compose.override.yml` | Operator-managed (image pin + port mapping + container name). Mirroring would clobber prod-specific deployment overrides. |
| `.env`, `.env.local` | Secrets. Master key + admin password + bouncer key live here. Never sync. |
| `data/`, `backups/` | Volume / data dirs. Defensive: not in repo anyway. |
| `.git/`, `.gitignore` | VCS state. Operator's branch state is theirs. |
| `node_modules/`, `dist/`, `frontend/dist/`, `frontend/.vite/` | Build outputs / caches. Regenerated by `docker compose build`. |
| `backend/static/assets/` | Embedded frontend bundle; emitted into the image during the multi-stage docker build. Git-ignored too. |
| `site/` | Generated mkdocs output. |
| `*.tar.gz` | Phase 0 archive + any other tarballs. |
| `.claude/`, `.vscode/`, `.idea/`, `.DS_Store`, `*.swp`, `*~` | Editor / agent / OS noise. |

Everything else mirrors. Argos-shipped repo files including
`crowdsec/config.yaml.local` (a CrowdSec-convention `.local`
override that argos owns directly) propagate normally.

### Refusing to run

`sync-prod.sh` exits with a clear error when:

- `ARGOS_PROD_DIR` doesn't exist (no auto-creation).
- `ARGOS_PROD_DIR` doesn't look like an argos checkout (no
  `docker-compose.yml` at the top level).
- The resolved source and destination are the same path.
- Stdin is not a TTY and `--yes` was not passed.
- `rsync` is not installed.

These are deliberate -- the script destroys files via `--delete`
within tracked subtrees, so a misconfigured invocation should
never silently apply.

### Verifying the deploy

Once the panel is healthy, run the post-deploy smokes:

```bash
SESSION=$(docker run --rm -v argos_prod_data:/data alpine sh -c \
    "apk add --no-cache sqlite >/dev/null 2>&1
     sqlite3 /data/argos.db \"
       SELECT token FROM sessions
        WHERE expires_at > datetime('now')
        ORDER BY id DESC LIMIT 1;\"")

ARGOS_SESSION_TOKEN="${SESSION}" make verify-prod
```

`make verify-prod` runs the v1.3.25 scenarios + appsec-tuning
smokes end-to-end against the running stack. Both verify the
EFFECT (cscli scenarios list reflects the panel intent;
argos-tuning.yaml regeneration produces the requested
threshold), not just panel emit.

## Recovery: drift between source and operational

If you suspect drift (panel showing one state, cscli showing
another), the canonical check is:

```bash
diff -rq ~/argos-edge/crowdsec/ ~/argos-prod/crowdsec/
diff ~/argos-edge/Caddyfile ~/argos-prod/Caddyfile
```

Anything reported as "differ" or "Only in argos-edge" is the
gap. `make sync-prod` reconciles.

For deeper drift (operator hand-edited a bind-mounted file in
the operational dir for an incident, never reverted), the diff
will show the divergence so you can decide: accept upstream
(let sync overwrite) or move the change upstream (commit it
in argos-edge, pull, then sync).

## Release-note checklist for changes that touch bind mounts

Authors of releases that change `crowdsec/*`, `Caddyfile`, or
`docker-compose.yml` should:

1. Note in the release notes that bind-mounted files changed.
2. Recommend `make deploy-prod` (or the manual rsync + build +
   up path) rather than just `docker compose up -d`.
3. If the new release adds a smoke for the touched surface,
   reference it in the release notes' Smoke section.

This page exists so that recommendation has a target to point
at.
