-- OIDC SSO + multi-user. Adds external-identity columns to users so a
-- row can represent either a local account (password + optional TOTP)
-- or an OIDC-provisioned account (no password, MFA delegated to the
-- provider). A single user MAY have both set simultaneously -- the
-- local admin bootstrapped by env vars can later bind to an OIDC
-- identity without losing the break-glass password path.
--
-- password_hash becomes nullable because OIDC-only users never have
-- one. SQLite ALTER COLUMN is not supported, so we rebuild the table
-- preserving every existing row + its TOTP state (added in 016) plus
-- the created_at / updated_at / last_login timestamps.
--
-- oidc_* settings rows hold the runtime config. client_secret lives
-- in oidc.client_secret_encrypted (AES-GCM, same master key that
-- encrypts the Phase 5 notification secrets).

CREATE TABLE users_new (
    id                            INTEGER PRIMARY KEY AUTOINCREMENT,
    username                      TEXT NOT NULL UNIQUE,
    password_hash                 TEXT,
    created_at                    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login                    TIMESTAMP,
    totp_secret_encrypted         TEXT,
    totp_enabled                  INTEGER NOT NULL DEFAULT 0,
    totp_enabled_at               TIMESTAMP,
    totp_recovery_codes_encrypted TEXT,
    external_id                   TEXT,
    external_provider             TEXT,
    email                         TEXT,
    display_name                  TEXT,
    created_via                   TEXT NOT NULL DEFAULT 'local'
);

INSERT INTO users_new (
    id, username, password_hash, created_at, updated_at, last_login,
    totp_secret_encrypted, totp_enabled, totp_enabled_at, totp_recovery_codes_encrypted
)
SELECT
    id, username, password_hash, created_at, updated_at, last_login,
    totp_secret_encrypted, totp_enabled, totp_enabled_at, totp_recovery_codes_encrypted
FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

-- Unique partial index on (external_provider, external_id) so two
-- rows cannot claim the same OIDC sub. Partial so NULLs don't clash.
CREATE UNIQUE INDEX idx_users_external
    ON users(external_provider, external_id)
    WHERE external_provider IS NOT NULL AND external_id IS NOT NULL;

-- OIDC runtime config. Defaults keep the feature OFF; flipping
-- oidc.enabled to "true" requires the operator to save a valid
-- issuer_url + client_id + client_secret via PUT /api/auth/oidc/config.
INSERT INTO settings (key, value) VALUES
    ('oidc.enabled',                 'false'),
    ('oidc.issuer_url',              ''),
    ('oidc.client_id',               ''),
    ('oidc.client_secret_encrypted', ''),
    ('oidc.scopes',                  'openid email profile'),
    ('oidc.cookie_parent_domain',    ''),
    ('oidc.auto_provision',          'true'),
    ('oidc.allowed_emails',          ''),
    ('oidc.allowed_domains',         '');
