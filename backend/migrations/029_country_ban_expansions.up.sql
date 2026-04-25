-- v1.3.21: country_ban_expansions persists the panel-side
-- expansion of operator-issued country bans into the equivalent
-- list of scope=Range LAPI decisions. Each row tracks one active
-- country expansion: the country_code, the JSON array of LAPI
-- decision IDs created when the ban was issued, and the MMDB
-- version at creation so a future MMDB refresh can reconcile
-- against the current CIDR list.
--
-- Why this table exists: hslatman/caddy-crowdsec-bouncer rejects
-- scope=Country in stream mode (internal/core/store.go L43-L58)
-- and live mode queries LAPI with IPEquals only -- so country
-- decisions never enforce at the Caddy edge. v1.3.20 confirmed
-- the upstream gap; v1.3.21 works around it by expanding country
-- bans into Range decisions panel-side, which the plugin handles
-- natively. This table is the source of truth for revocation:
-- without it, "ban country BR" would create N decisions whose
-- shared origin is irrecoverable.
--
-- UNIQUE(country_code) is deliberate: an operator-issued country
-- ban is an idempotent intent. Re-issuing replaces the existing
-- expansion (caller deletes old decisions then inserts new ones)
-- so the MMDB version recorded stays current.
CREATE TABLE country_ban_expansions (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    country_code             TEXT NOT NULL,
    decision_ids             TEXT NOT NULL,
    cidr_count               INTEGER NOT NULL,
    reason                   TEXT NOT NULL DEFAULT '',
    duration                 TEXT NOT NULL,
    created_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by               TEXT NOT NULL,
    mmdb_version_at_creation TEXT NOT NULL,
    UNIQUE(country_code)
);
