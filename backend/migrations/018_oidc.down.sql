DELETE FROM settings WHERE key IN (
    'oidc.enabled',
    'oidc.issuer_url',
    'oidc.client_id',
    'oidc.client_secret_encrypted',
    'oidc.scopes',
    'oidc.cookie_parent_domain',
    'oidc.auto_provision',
    'oidc.allowed_emails',
    'oidc.allowed_domains'
);

DROP INDEX IF EXISTS idx_users_external;

-- Rebuild to pre-018 shape: drop the five external-identity columns
-- and restore NOT NULL on password_hash. OIDC-only users (those with
-- NULL password_hash) would break the restored constraint; treat
-- that as an operator error (rolling back OIDC while OIDC-only
-- accounts exist is itself a misuse) and let the INSERT fail loudly
-- rather than silently drop rows.
CREATE TABLE users_old (
    id                            INTEGER PRIMARY KEY AUTOINCREMENT,
    username                      TEXT NOT NULL UNIQUE,
    password_hash                 TEXT NOT NULL,
    created_at                    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login                    TIMESTAMP,
    totp_secret_encrypted         TEXT,
    totp_enabled                  INTEGER NOT NULL DEFAULT 0,
    totp_enabled_at               TIMESTAMP,
    totp_recovery_codes_encrypted TEXT
);

INSERT INTO users_old (
    id, username, password_hash, created_at, updated_at, last_login,
    totp_secret_encrypted, totp_enabled, totp_enabled_at, totp_recovery_codes_encrypted
)
SELECT
    id, username, password_hash, created_at, updated_at, last_login,
    totp_secret_encrypted, totp_enabled, totp_enabled_at, totp_recovery_codes_encrypted
FROM users
WHERE password_hash IS NOT NULL;

DROP TABLE users;
ALTER TABLE users_old RENAME TO users;
