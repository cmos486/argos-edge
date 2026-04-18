-- Revert log_entries to phase-3.5 shape (no waf_* columns, no waf_audit
-- source). All waf_audit rows are dropped in the rebuild.
CREATE TABLE log_entries_old (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TIMESTAMP NOT NULL,
    source       TEXT NOT NULL
        CHECK (source IN ('caddy_access', 'caddy_error', 'audit')),
    level        TEXT NOT NULL DEFAULT '',
    host_id      INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    host_domain  TEXT NOT NULL DEFAULT '',
    rule_id      INTEGER REFERENCES rules(id) ON DELETE SET NULL,
    remote_ip    TEXT NOT NULL DEFAULT '',
    method       TEXT NOT NULL DEFAULT '',
    path         TEXT NOT NULL DEFAULT '',
    status       INTEGER NOT NULL DEFAULT 0,
    duration_ms  INTEGER NOT NULL DEFAULT 0,
    size_bytes   INTEGER NOT NULL DEFAULT 0,
    user_agent   TEXT NOT NULL DEFAULT '',
    upstream     TEXT NOT NULL DEFAULT '',
    message      TEXT NOT NULL DEFAULT '',
    raw          TEXT NOT NULL DEFAULT ''
);

INSERT INTO log_entries_old
    (id, timestamp, source, level, host_id, host_domain, rule_id,
     remote_ip, method, path, status, duration_ms, size_bytes,
     user_agent, upstream, message, raw)
SELECT id, timestamp, source, level, host_id, host_domain, rule_id,
       remote_ip, method, path, status, duration_ms, size_bytes,
       user_agent, upstream, message, raw
  FROM log_entries
 WHERE source != 'waf_audit';

DROP INDEX IF EXISTS idx_log_entries_waf_rule_ts;
DROP INDEX IF EXISTS idx_log_entries_status_ts;
DROP INDEX IF EXISTS idx_log_entries_rule_ts;
DROP INDEX IF EXISTS idx_log_entries_host_ts;
DROP INDEX IF EXISTS idx_log_entries_source_ts;
DROP INDEX IF EXISTS idx_log_entries_timestamp;
DROP TABLE log_entries;
ALTER TABLE log_entries_old RENAME TO log_entries;
CREATE INDEX idx_log_entries_timestamp  ON log_entries(timestamp DESC);
CREATE INDEX idx_log_entries_source_ts  ON log_entries(source, timestamp DESC);
CREATE INDEX idx_log_entries_host_ts    ON log_entries(host_id, timestamp DESC);
CREATE INDEX idx_log_entries_rule_ts    ON log_entries(rule_id, timestamp DESC);
CREATE INDEX idx_log_entries_status_ts  ON log_entries(status, timestamp DESC);

DROP INDEX IF EXISTS idx_waf_custom_rules_host;
DROP TABLE IF EXISTS waf_custom_rules;
DROP INDEX IF EXISTS idx_waf_exclusions_host;
DROP TABLE IF EXISTS waf_exclusions;
DROP TABLE IF EXISTS host_security;
