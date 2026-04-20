# CLI

The argos binary speaks three subcommands in addition to the
default server-run mode. All three are operator-facing break-glass
tools and write audit rows where applicable.

```
argos                                  # run the panel (default)
argos migrate rollback                 # undo the most recent migration
argos restore --file <path> --yes      # replace DB from a backup archive
argos disable-2fa --user <name> --yes  # clear a user's TOTP state
```

Every subcommand ignores any HTTP traffic — they operate directly
against the argos_data volume. They are designed to run inside the
container via `docker compose exec argos <cmd>`.

## `argos` (default)

Runs the panel. No flags. Configuration via environment variables
listed in [Env vars](env-vars.md).

Respects SIGINT / SIGTERM with a 10 s graceful-shutdown deadline
for background goroutines.

## `argos migrate rollback`

Rolls back the most recently applied schema migration by running
its `.down.sql` (or its Go down hook when registered) and deleting
the corresponding `schema_migrations` row.

**Use with care.** Production never calls this; the expected path
for reverting a bad migration is [restoring a backup](../workflows/restore-backup.md).
The subcommand exists for sandbox work — dev iterations of a
migration file, or undoing a test migration you just applied.

Flags: none.

Exits non-zero on:

- Nothing to roll back (empty `schema_migrations`).
- Down file missing from the embedded FS AND no Go hook registered.
- Down SQL errors (DB is left in the pre-rollback state via the
  transaction).

Example:

```bash
docker compose exec argos argos migrate rollback
# INFO rolled back migration version=020_oidc_require_email_verified
```

## `argos restore --file <path> --yes`

Replaces the live DB with the content of a backup tar.gz. Both
flags are required.

**Operational semantics:**

1. Validates the archive's metadata.json + sha256 (if the row is
   in the `backups` table).
2. Writes `/data/.restore_pending` with the archive path.
3. Exits 0 to indicate the restore is scheduled.
4. On the next container start, the pre-boot path reads the marker
   and extracts the tar.gz over `/data`, then clears the marker.

You MUST `docker compose restart argos` after the CLI exits for the
restore to actually take effect.

Flags:

| Flag | Required | Notes |
|---|---|---|
| `--file <path>` | yes | Path (inside container) to the tar.gz. Typically `/data/backups/argos-backup-<ts>.tar.gz`. |
| `--yes` | yes | Confirmation flag. Prevents accidental invocations. |

Example:

```bash
docker compose cp ./argos-backup-20260418-021500.tar.gz \
  argos:/data/backups/

docker compose exec argos \
  argos restore --file /data/backups/argos-backup-20260418-021500.tar.gz --yes

docker compose restart argos
```

Failure modes:

- Archive missing or unreadable → non-zero exit, no marker written.
- Archive sha256 does not match the row in `backups` → warning
  log, restore still proceeds (covers the orphan-archive case).
- Marker already exists → error; a prior pending restore has not
  been consumed yet. `rm /data/.restore_pending` if you want to
  abort the pending one.

Full flow: [Restore from backup](../workflows/restore-backup.md).

## `argos disable-2fa --user <username> --yes`

Break-glass TOTP reset. Clears `totp_secret_encrypted`,
`totp_enabled`, `totp_enabled_at`, `totp_recovery_codes_encrypted`
for one user.

**Use when:**

- The operator lost their authenticator AND ran out of recovery
  codes.
- A user ID-claim is that they forgot the authenticator AND the
  recovery codes, and you verify out-of-band before running.

Flags:

| Flag | Required | Notes |
|---|---|---|
| `--user <username>` | yes | Exact (case-sensitive) match. |
| `--yes` | yes | Confirmation. |

Audit: writes a `totp_disabled` audit row with
`source="cli"` and `username=<name>`. The action is attributable
to the CLI even though there is no session user.

The password is NOT changed. The user logs in with their existing
password after this; they should re-enroll TOTP immediately.

Example:

```bash
docker compose exec argos argos disable-2fa --user admin --yes
# INFO disabled totp for user admin via CLI
```

## What the CLI does NOT do

- **No create-user** subcommand. New admins come through OIDC
  auto-provisioning or the env-var bootstrap (first boot only).
  See [Onboard an admin](../workflows/onboard-admin.md).
- **No rotate-password** subcommand. Rotate via direct SQL if you
  must; there is no CLI primitive.
- **No vacuum** subcommand. Vacuum happens on the retention cron's
  monthly schedule; kick a manual VACUUM with
  `docker compose exec argos sqlite3 /data/argos.db VACUUM` if
  needed.
- **No delete-user** subcommand. Direct SQL required. The
  `users.id` FK cascade handles dependent rows (sessions, TOTP
  attempts) via `ON DELETE CASCADE`.
- **No cron commands**. All cron work is internal to the running
  panel; there is nothing to "fire now" externally except the
  HTTP endpoints that trigger backup / geoip refresh manually.

## Related

- [Installation](../getting-started/installation.md) — where the
  container comes from.
- [Troubleshooting](../operations/troubleshooting.md) — operator
  problems that the CLI solves.
- [API](api.md) — HTTP counterparts.
