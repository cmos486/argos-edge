-- Hosts managed by the panel. A host pairs a domain with an upstream URL
-- plus TLS intent; Caddy is reconciled from this table via Admin API.
CREATE TABLE hosts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT NOT NULL UNIQUE,
    upstream_url TEXT NOT NULL,
    tls_mode     TEXT NOT NULL DEFAULT 'auto',  -- 'auto' | 'none'
    tls_email    TEXT NOT NULL DEFAULT '',
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (tls_mode IN ('auto', 'none'))
);

CREATE INDEX idx_hosts_enabled ON hosts(enabled);

-- Read-only mirror of the certificates Caddy has issued. Populated by
-- /api/certs on demand from the Admin API; kept as a table so later
-- phases can add expiry alerts without changing the shape.
CREATE TABLE cert_status (
    domain           TEXT PRIMARY KEY,
    issuer           TEXT NOT NULL DEFAULT '',
    not_after        TIMESTAMP,
    last_checked_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
