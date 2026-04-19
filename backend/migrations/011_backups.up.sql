-- Phase 9a: local backup + restore.
--
-- One row per tar.gz the manager produces. filename is unique so the
-- scheduler cannot accidentally overwrite an earlier backup if the
-- clock skips.  trigger_user_id is NULL for scheduled backups so the
-- history still resolves when the user is deleted.

CREATE TABLE backups (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    filename         TEXT NOT NULL UNIQUE,
    size_bytes       INTEGER NOT NULL,
    sha256           TEXT NOT NULL,
    kind             TEXT NOT NULL CHECK (kind IN ('manual', 'scheduled')),
    trigger_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note             TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_backups_created_at ON backups(created_at DESC);

-- Seed backup settings. backup.path is NOT writable from the UI --
-- it is mounted in from docker-compose and only configurable via
-- environment variables, so it lives in settings purely for display.
INSERT INTO settings (key, value) VALUES
    ('backup.enabled',        'true'),
    ('backup.schedule',       '0 2 * * *'),
    ('backup.retention_days', '14'),
    ('backup.path',           '/data/backups');
