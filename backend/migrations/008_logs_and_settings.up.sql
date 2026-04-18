-- Unified log store + key/value settings.
--
-- log_entries denormalizes host_domain so rows survive a host delete;
-- rule_id keeps its FK ON DELETE SET NULL to preserve history without
-- dangling refs. raw is the original JSON line from Caddy (or the
-- audit payload) kept for debug / drawer rendering.
CREATE TABLE log_entries (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TIMESTAMP NOT NULL,
    source        TEXT NOT NULL
        CHECK (source IN ('caddy_access', 'caddy_error', 'audit')),
    level         TEXT NOT NULL DEFAULT '',
    host_id       INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    host_domain   TEXT NOT NULL DEFAULT '',
    rule_id       INTEGER REFERENCES rules(id) ON DELETE SET NULL,
    remote_ip     TEXT NOT NULL DEFAULT '',
    method        TEXT NOT NULL DEFAULT '',
    path          TEXT NOT NULL DEFAULT '',
    status        INTEGER NOT NULL DEFAULT 0,
    duration_ms   INTEGER NOT NULL DEFAULT 0,
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    user_agent    TEXT NOT NULL DEFAULT '',
    upstream      TEXT NOT NULL DEFAULT '',
    message       TEXT NOT NULL DEFAULT '',
    raw           TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_log_entries_timestamp        ON log_entries(timestamp DESC);
CREATE INDEX idx_log_entries_source_ts        ON log_entries(source, timestamp DESC);
CREATE INDEX idx_log_entries_host_ts          ON log_entries(host_id, timestamp DESC);
CREATE INDEX idx_log_entries_rule_ts          ON log_entries(rule_id, timestamp DESC);
CREATE INDEX idx_log_entries_status_ts        ON log_entries(status, timestamp DESC);

CREATE TABLE settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Seed defaults. offsets start at 0 so a fresh install re-ingests any
-- existing log files (which are themselves fresh).
INSERT INTO settings (key, value) VALUES
    ('logs.retention_days', '30'),
    ('logs.max_entries',    '500000'),
    ('logs.access_offset',  '0'),
    ('logs.errors_offset',  '0');
