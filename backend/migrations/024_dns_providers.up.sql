-- v1.3 Feature: native catalogue of DNS providers for ACME DNS-01.
--
-- Pre v1.3, the caddy container was built with one caddy-dns plugin
-- (cloudflare) and the token was read from its environment via the
-- {env.CLOUDFLARE_API_TOKEN} placeholder. This table moves provider
-- credentials into the panel DB (encrypted, same AES-GCM master key
-- that protects OIDC client secrets / VAPID key / manual cert keys).
--
-- Sub-phase A ships cloudflare + route53. Later sub-phases extend the
-- CHECK with a writable_schema migration (pattern from 023) when
-- adding providers. Seed rows are INSERT OR IGNORE so re-running the
-- migration (which we do not, but defensive against backup restores
-- that replay up files) does not clobber operator-configured rows.
--
-- credentials_encrypted holds the argos1: prefixed ciphertext of a
-- JSON blob: {"api_token":"..."} for cloudflare,
-- {"access_key_id":"...","secret_access_key":"...","region":"..."}
-- for route53. The exact shape is owned by internal/dnsproviders
-- (the catalogue), not the DB -- the column is deliberately opaque.

CREATE TABLE dns_providers (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    name                  TEXT NOT NULL UNIQUE
                              CHECK (name IN ('cloudflare', 'route53')),
    enabled               INTEGER NOT NULL DEFAULT 0
                              CHECK (enabled IN (0, 1)),
    credentials_encrypted BLOB,
    updated_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_dns_providers_enabled ON dns_providers(enabled);

INSERT OR IGNORE INTO dns_providers (name, enabled) VALUES
    ('cloudflare', 0),
    ('route53',    0);
