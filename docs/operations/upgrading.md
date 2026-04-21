# Upgrading

Argos upgrades are git pull + compose pull + up. Schema migrations
run automatically on container start; the runner skips anything
already applied.

## Standard upgrade

```bash
cd argos-edge
git fetch --tags
git log HEAD..origin/main --oneline  # read what's changing
git pull

docker compose pull
docker compose up -d
```

The binary comes back up in a few seconds. If any new migrations
were included, the boot log has `INFO applied migration
version=XXX_...` lines for each one.

## Always back up first

Even if the release notes say "no schema changes":

1. **Backups tab → New backup** (manual, kind=manual).
2. Wait for the new row to appear with `status=sent`.
3. Copy the tar.gz off-host if you have an off-site mirror.

An argos backup captures the DB + the Caddy state (if readable).
Restoring is a one-liner if the upgrade does something unexpected.

## Release notes

Tag releases live at
<https://github.com/cmos486/argos-edge/releases>. The project
follows semver at major-version granularity:

- **Patch** (`v1.0.1 -> v1.0.2`): bug fixes, no schema.
- **Minor** (`v1.0.x -> v1.1.0`): new features, additive migrations.
  Safe to upgrade without reading closely.
- **Major** (`v1.x -> v2.0`): breaking changes. READ the release
  notes, back up, test on a staging copy if you can.

## Rollback

If an upgrade does not work out:

```bash
# Stop the stack but KEEP the volumes.
docker compose down

# Check out the previous tag.
git checkout v1.0.3  # or whatever you were on

# Rebuild and restart.
docker compose pull
docker compose up -d
```

One caveat: argos does NOT automatically run down migrations on
downgrade. If the new version applied a migration that the old
version does not understand, the old version's migration runner
will not complain (it only checks forward) but runtime code will
fail to read a new column.

Paths out when a downgrade is blocked by schema:

1. **Rollback migration manually** from the CLI:

    ```bash
    docker compose exec argos argos migrate rollback
    ```

    Repeat per migration to rewind. Only use in development /
    sandbox — production should prefer **Restore from backup**
    below.

2. **Restore a pre-upgrade backup**:

    ```bash
    docker compose exec argos \
      argos restore --file /data/backups/argos-backup-<pre-upgrade-ts>.tar.gz --yes
    docker compose restart argos
    ```

    Schema matches whatever the backup was taken at.

## Docker image caveats

- `docker compose pull` re-fetches the images the compose file
  references. If the repo tracks `latest`, you get whatever is
  tagged latest now. For reproducible upgrades, pin the tag in
  `docker-compose.yml` and bump explicitly.
- The `argos` image is multi-stage built in CI; the panel's SPA
  is embedded, so the image is fully self-contained. No separate
  frontend container to upgrade.

## Breaking-change checklist

When the release notes say "breaking":

- [ ] Read the full release notes. Migrate paths are documented
      per-release.
- [ ] Take a manual backup. Verify the row appears.
- [ ] If off-site replication exists, verify the last sync was
      successful.
- [ ] Note the current version (`docker compose exec argos argos
      --version` if implemented, or check the running image tag).
- [ ] Perform the upgrade on a staging copy first if the blast
      radius is unclear.
- [ ] Read the post-upgrade log: `docker compose logs argos
      --since=5m | grep -iE 'error|warn'`. Clean the warnings.
- [ ] Smoke test the critical flows: login, one host reachable,
      one backup.

## Upgrading Caddy and CrowdSec

The compose file pins versions for `caddy` and `crowdsec` images.
Upgrading them is independent of argos:

- `caddy` — bump the tag in `docker-compose.yml`. Config is
  written by argos on boot so no manual Caddyfile edits survive.
- `crowdsec` — bump the tag. The LAPI DB schema migrates
  on first boot after the bump; might take 1-2 minutes on a
  panel with a large decision set.

Major-version bumps of either image can change the behaviour
argos depends on (bouncer plugin API, AppSec listener shape,
access log JSON keys). Treat them with the same care as argos
majors.

## What changes survive an upgrade

Anything persisted in SQLite or in the `argos_data` volume
survives:

- Hosts, target groups, targets, rules, security policies.
- Users, sessions (unless session TTL expired during the downtime).
- Notifications channels + rules + deliveries history.
- Backups (including the one you just took).
- Settings, including OIDC config, TOTP enrollments, recovery
  codes.

What does NOT survive a major upgrade automatically:

- In-memory state (OIDC pending flows, TOTP challenge store,
  ForwardAuth cache). All of these rebuild on first use.
- Docker volume contents IF you also run `docker compose down -v`
  (the `-v` wipes volumes; avoid unless you mean it).

!!! danger "Never `docker compose down -v` during an upgrade"
    `-v` drops every named volume — including `argos_data` which
    holds `argos.db`. Plain `docker compose down` stops the stack
    but keeps volumes; that is the upgrade flow. If you accidentally
    ran `-v`, the only recovery is restoring a backup tarball onto
    the fresh volumes. Keep `.env` alongside the backup so
    `ARGOS_MASTER_KEY` decrypts the secrets.

## Related

- [Backups](../features/backups.md) — take one before every
  upgrade.
- [Restore from backup](../workflows/restore-backup.md) —
  rollback path.
- [Migrations README](https://github.com/cmos486/argos-edge/blob/main/backend/migrations/README.md)
  — schema policy details.
