-- Phase 9a polish: the reconcile pass on startup inserts rows for
-- tar.gz files that lack metadata.json, with kind='orphan'. SQLite
-- does not support adding to a CHECK constraint in place, so rebuild.

CREATE TABLE backups_new (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    filename         TEXT NOT NULL UNIQUE,
    size_bytes       INTEGER NOT NULL,
    sha256           TEXT NOT NULL,
    kind             TEXT NOT NULL CHECK (kind IN ('manual', 'scheduled', 'orphan')),
    trigger_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note             TEXT NOT NULL DEFAULT ''
);

INSERT INTO backups_new (id, filename, size_bytes, sha256, kind, trigger_user_id, created_at, note)
SELECT id, filename, size_bytes, sha256, kind, trigger_user_id, created_at, note FROM backups;

DROP INDEX IF EXISTS idx_backups_created_at;
DROP TABLE backups;
ALTER TABLE backups_new RENAME TO backups;
CREATE INDEX idx_backups_created_at ON backups(created_at DESC);
