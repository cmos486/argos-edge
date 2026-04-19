-- Phase 2FA: per-user TOTP (RFC 6238) with recovery codes.
--
-- The secret + recovery codes are encrypted at rest with the same
-- AES-GCM master key the notifications package already uses (env var
-- ARGOS_MASTER_KEY). totp_enabled is the authoritative flag: a user
-- may have a half-provisioned secret (setup started, not verified yet)
-- and we only flip the flag once the first 6-digit code validates.
--
-- totp_attempts mirrors login_attempts but is keyed by user_id so the
-- 5-fails-in-15-min / 30-min-ban rule is per-user rather than per-IP.
-- Pairing (user_id, ip) in the index lets the limiter pivot either way
-- without a table scan.

ALTER TABLE users ADD COLUMN totp_secret_encrypted        TEXT;
ALTER TABLE users ADD COLUMN totp_enabled                 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_enabled_at              TIMESTAMP;
ALTER TABLE users ADD COLUMN totp_recovery_codes_encrypted TEXT;

CREATE TABLE totp_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip           TEXT NOT NULL,
    success      INTEGER NOT NULL DEFAULT 0,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_totp_attempts_user_ip_time ON totp_attempts(user_id, ip, attempted_at DESC);
CREATE INDEX idx_totp_attempts_time         ON totp_attempts(attempted_at DESC);
