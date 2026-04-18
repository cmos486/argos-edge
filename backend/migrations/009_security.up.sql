-- Phase 4 security tables: per-host WAF and rate-limit settings, CRS
-- rule exclusions, and custom SecRule text. Also extends log_entries
-- with Coraza-audit columns and adds 'waf_audit' to the source CHECK.
--
-- host_security has a 1:1 with hosts via PK host_id + ON DELETE CASCADE,
-- so deleting a host drops its security config atomically. Default row
-- values reflect "WAF off, rate-limit off"; the backfill at the bottom
-- seeds one row per existing host.

CREATE TABLE host_security (
    host_id                    INTEGER PRIMARY KEY
        REFERENCES hosts(id) ON DELETE CASCADE,
    waf_enabled                INTEGER NOT NULL DEFAULT 0,
    waf_mode                   TEXT    NOT NULL DEFAULT 'detect'
        CHECK (waf_mode IN ('detect', 'block')),
    waf_paranoia               INTEGER NOT NULL DEFAULT 1
        CHECK (waf_paranoia BETWEEN 1 AND 4),
    waf_block_status           INTEGER NOT NULL DEFAULT 403,
    waf_block_body             TEXT    NOT NULL DEFAULT '',
    rate_limit_enabled         INTEGER NOT NULL DEFAULT 0,
    rate_limit_requests        INTEGER NOT NULL DEFAULT 0,
    rate_limit_window_seconds  INTEGER NOT NULL DEFAULT 0,
    rate_limit_key             TEXT    NOT NULL DEFAULT 'ip'
        CHECK (rate_limit_key IN ('ip', 'header', 'global')),
    rate_limit_header_name     TEXT    NOT NULL DEFAULT '',
    rate_limit_status          INTEGER NOT NULL DEFAULT 429,
    updated_at                 TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- path_pattern NOT NULL DEFAULT '' (empty = global exclusion) so the
-- UNIQUE constraint below behaves intuitively: one global + one per
-- non-empty path per (host, rule).
CREATE TABLE waf_exclusions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id        INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    crs_rule_id    INTEGER NOT NULL CHECK (crs_rule_id > 0),
    path_pattern   TEXT    NOT NULL DEFAULT '',
    reason         TEXT    NOT NULL DEFAULT '',
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (host_id, crs_rule_id, path_pattern)
);

CREATE INDEX idx_waf_exclusions_host ON waf_exclusions(host_id);

CREATE TABLE waf_custom_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL DEFAULT '',
    secrule     TEXT    NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_waf_custom_rules_host ON waf_custom_rules(host_id);

-- Extend log_entries: rebuild to both widen the source CHECK and add
-- Coraza audit columns in one pass.
CREATE TABLE log_entries_new (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp          TIMESTAMP NOT NULL,
    source             TEXT NOT NULL
        CHECK (source IN ('caddy_access', 'caddy_error', 'audit', 'waf_audit')),
    level              TEXT NOT NULL DEFAULT '',
    host_id            INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    host_domain        TEXT NOT NULL DEFAULT '',
    rule_id            INTEGER REFERENCES rules(id) ON DELETE SET NULL,
    remote_ip          TEXT NOT NULL DEFAULT '',
    method             TEXT NOT NULL DEFAULT '',
    path               TEXT NOT NULL DEFAULT '',
    status             INTEGER NOT NULL DEFAULT 0,
    duration_ms        INTEGER NOT NULL DEFAULT 0,
    size_bytes         INTEGER NOT NULL DEFAULT 0,
    user_agent         TEXT NOT NULL DEFAULT '',
    upstream           TEXT NOT NULL DEFAULT '',
    message            TEXT NOT NULL DEFAULT '',
    raw                TEXT NOT NULL DEFAULT '',
    waf_rule_id        INTEGER NOT NULL DEFAULT 0,
    waf_rule_message   TEXT    NOT NULL DEFAULT '',
    waf_severity       TEXT    NOT NULL DEFAULT '',
    waf_anomaly_score  INTEGER NOT NULL DEFAULT 0
);

INSERT INTO log_entries_new
    (id, timestamp, source, level, host_id, host_domain, rule_id,
     remote_ip, method, path, status, duration_ms, size_bytes,
     user_agent, upstream, message, raw)
SELECT
     id, timestamp, source, level, host_id, host_domain, rule_id,
     remote_ip, method, path, status, duration_ms, size_bytes,
     user_agent, upstream, message, raw
FROM log_entries;

DROP INDEX IF EXISTS idx_log_entries_status_ts;
DROP INDEX IF EXISTS idx_log_entries_rule_ts;
DROP INDEX IF EXISTS idx_log_entries_host_ts;
DROP INDEX IF EXISTS idx_log_entries_source_ts;
DROP INDEX IF EXISTS idx_log_entries_timestamp;
DROP TABLE log_entries;
ALTER TABLE log_entries_new RENAME TO log_entries;
CREATE INDEX idx_log_entries_timestamp    ON log_entries(timestamp DESC);
CREATE INDEX idx_log_entries_source_ts    ON log_entries(source, timestamp DESC);
CREATE INDEX idx_log_entries_host_ts      ON log_entries(host_id, timestamp DESC);
CREATE INDEX idx_log_entries_rule_ts      ON log_entries(rule_id, timestamp DESC);
CREATE INDEX idx_log_entries_status_ts    ON log_entries(status, timestamp DESC);
CREATE INDEX idx_log_entries_waf_rule_ts  ON log_entries(waf_rule_id, timestamp DESC);

-- Seed host_security defaults for every existing host.
INSERT INTO host_security (host_id)
SELECT id FROM hosts
WHERE id NOT IN (SELECT host_id FROM host_security);
