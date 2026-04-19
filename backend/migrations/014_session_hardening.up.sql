-- Phase 9b operational hardening.
--
-- 1. Extend sessions with last_seen_at to enforce an idle timeout
--    independent of the absolute TTL. created_at already exists.
-- 2. Track login attempts per (remote_ip, timestamp) so the Login
--    handler can rate-limit with a 5-fails-in-5-min rule and a
--    30-minute ban window.
-- 3. Seed three new settings: session.absolute_timeout_hours (7d),
--    session.idle_timeout_hours (24h), panel.security_headers_strict
--    (reserved for future opt-out; defaults true).

ALTER TABLE sessions ADD COLUMN last_seen_at TIMESTAMP;
-- Back-fill existing rows so they don't immediately idle-out.
UPDATE sessions SET last_seen_at = created_at WHERE last_seen_at IS NULL;

CREATE TABLE login_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    remote_ip  TEXT NOT NULL,
    username   TEXT NOT NULL,
    success    INTEGER NOT NULL DEFAULT 0,
    timestamp  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_login_attempts_ip_ts  ON login_attempts(remote_ip, timestamp DESC);
CREATE INDEX idx_login_attempts_ts     ON login_attempts(timestamp DESC);

INSERT INTO settings (key, value) VALUES
    ('session.absolute_timeout_hours', '168'),
    ('session.idle_timeout_hours',     '24'),
    ('panel.security_headers_strict',  'true');
