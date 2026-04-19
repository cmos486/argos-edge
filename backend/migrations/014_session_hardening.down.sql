DELETE FROM settings WHERE key IN (
    'session.absolute_timeout_hours',
    'session.idle_timeout_hours',
    'panel.security_headers_strict'
);

DROP INDEX IF EXISTS idx_login_attempts_ts;
DROP INDEX IF EXISTS idx_login_attempts_ip_ts;
DROP TABLE IF EXISTS login_attempts;

-- SQLite does not support DROP COLUMN prior to 3.35. The modernc
-- driver supports it (3.49 as of phase 9b). Rebuild is safer.
CREATE TABLE sessions_new (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token      TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);
INSERT INTO sessions_new (id, user_id, token, created_at, expires_at)
SELECT id, user_id, token, created_at, expires_at FROM sessions;

DROP INDEX IF EXISTS idx_sessions_token;
DROP INDEX IF EXISTS idx_sessions_user_id;
DROP INDEX IF EXISTS idx_sessions_expires_at;

DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;

CREATE INDEX idx_sessions_token      ON sessions(token);
CREATE INDEX idx_sessions_user_id    ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
