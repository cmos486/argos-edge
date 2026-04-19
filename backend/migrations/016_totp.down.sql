DROP INDEX IF EXISTS idx_totp_attempts_time;
DROP INDEX IF EXISTS idx_totp_attempts_user_ip_time;
DROP TABLE IF EXISTS totp_attempts;

-- SQLite DROP COLUMN is available in 3.35+ (modernc driver ships 3.49
-- as of phase 9b), but rebuilding is more portable and lets us keep
-- the exact original column order for the reverted schema.
CREATE TABLE users_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login    TIMESTAMP
);
INSERT INTO users_new (id, username, password_hash, created_at, updated_at, last_login)
SELECT id, username, password_hash, created_at, updated_at, last_login FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
