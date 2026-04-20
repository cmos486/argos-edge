# Migrations

Schema migrations for the argos SQLite database. Applied automatically at
boot by `internal/db.Migrate`; no manual step for operators.

## Runner invariants

The runner lives in `internal/db/migrate.go`. Contract:

- **Applied set is tracked in `schema_migrations(version, applied_at)`.**
  Each version can only be applied once; the runner consults this table
  to skip anything already on disk.
- **Lexical order.** Versions are sorted as strings, not numbers, so
  prefixes must be zero-padded to match. `002_foo` runs before
  `010_bar`. Ordering is stable regardless of file mtime.
- **Forward-only at boot.** Boot only ever runs `Migrate()` which
  applies pending up migrations. `Rollback()` exists but is only
  invoked by the `argos migrate rollback` subcommand during
  development; production never calls it.
- **Transactional per version.** Every `.up.sql` is executed inside a
  single `BEGIN` / `COMMIT`; a half-applied migration rolls back
  cleanly and leaves `schema_migrations` untouched, so the next boot
  retries the same version.
- **Go hooks bypass matching SQL.** When a version has a registered
  `UpHooks[version]` entry in `migrations.go`, the hook owns the
  transaction and the corresponding `.up.sql` (if any) is ignored.
  This is how migration 005 migrates `hosts.upstream_url` into the
  new `target_groups` / `targets` tables.
- **Idempotent.** Calling `Migrate()` twice in a row is a no-op on the
  second call. Covered by `TestMigrateIsIdempotent`.

## File naming

```
<version>_<snake_case_description>.up.sql
<version>_<snake_case_description>.down.sql
```

- `version` is 3 digits zero-padded: `001`, `002`, ..., `020`.
- Description is free-form but `snake_case` and short.
- Every up file has a matching down file, even if the down is a
  no-op. This keeps `migrate rollback` universally available during
  development.

Go hooks live next to the SQL files as `<version>_<description>.go`
inside the `migrations` package. They must be registered in the
`UpHooks` (and `DownHooks` when present) map in `migrations.go`.

## Adding a new migration

1. Pick the next free version number. Check `ls *.up.sql | sort` and
   pick `N+1`. Do not reuse a gap (see below about `013`).
2. Create `<version>_<desc>.up.sql` with the DDL or DML. Wrap each
   logical chunk with a brief comment explaining what and why.
3. Create `<version>_<desc>.down.sql` with the exact inverse. For
   additive changes this is a `DROP TABLE` or `DELETE FROM settings
   WHERE key = ...`; for rebuilds it is the mirror rebuild.
4. If the migration touches existing data in a way the SQL engine
   cannot express (URL parsing, conditional row transforms, a backfill
   that depends on row content), add a Go hook instead - see the
   `SQL vs Go hook` section below.
5. Run `go test ./internal/db/...` - the migration tests will catch
   syntax errors, bad ordering, or a schema shape that breaks the
   partial-apply path.
6. Update the application code that reads the new schema. Never commit
   a migration on its own without the code that needs it.

## SQL vs Go hook

Use **pure SQL** when:

- Creating or dropping tables, columns, indexes.
- Adding seed rows with fixed values.
- Rebuilding a table (SQLite has no `ALTER COLUMN`, so widening a
  `CHECK` or making a column nullable requires a `CREATE TABLE
  _new; INSERT ... SELECT; DROP; RENAME` dance done in SQL). See
  migrations 007, 009, 012, 018 for reference.

Use a **Go hook** when:

- You need to parse values to decide what row to insert (URL parsing,
  JSON shaping, regex-driven conditional updates).
- The backfill depends on another running service (geoip lookup
  during a migration - don't, but if you ever have to, a Go hook is
  the only way).
- You need to fail fast with a structured error rather than a raw
  SQL constraint failure (migration 005 refuses to migrate hosts with
  empty upstream URLs and bails with a clear message).

If a migration is mostly SQL with one dynamic value, keep it SQL and
compute the value at application boot time in a separate code path
instead of reaching for a hook.

## Gaps in the version sequence

**`013` does not exist.** It was retracted during development and the
version number was burned to avoid re-using an identifier that had
already been checked in briefly. The runner does not care about gaps
- it just picks up whatever `.up.sql` files are present. Future
migrations should continue from the next available number, not fill
the gap.

## Down migrations

The `.down.sql` files exist but the production runner never executes
them at boot. They are used by:

- The `argos migrate rollback` CLI subcommand, for sandbox testing.
- The test suite (`TestRollbackLastMigration`) to verify that each
  down is a real inverse of its up - important because a broken
  rollback would silently pass on upgrades while quietly destroying
  a dev sandbox.

A down file that just `DROP TABLE`s a migration that was "rebuild a
table" is fine; it does not restore the prior CHECK constraint, but
production never rolls back so the asymmetry is acceptable.

## Squash policy

The migration set will not be squashed into a single baseline at
v1.0.0. The cost of a baseline-virtual runner (detecting "this DB is
already past the baseline, skip it") exceeds the benefit of a cleaner
file listing at current size. The decision and full analysis live in
the Fase 4 security/maintenance sweep transcript.

Revisit when any of these becomes true:

- **Version count exceeds 40.** Roughly estimated 2-3 years of
  development at the current pace. At that size the file listing
  starts to matter for contributor onboarding.
- **A major version jump with pre-planned break-compat is on the
  roadmap.** For example v1.x -> v3.0 with "backup required, not
  compatible with v1.x databases" semantics. That is the natural
  free moment to drop the accumulated history.
- **A core table needs a fundamental redesign.** If `users`, `hosts`
  or `log_entries` has to be refactored in a way that 5+ of the
  existing migrations become misleading reading material for future
  contributors, that is a valid trigger even below 40 migrations.

None of these applies today.
