-- Companion to migration 024. Every host that selects tls_challenge='dns'
-- needs to know WHICH provider Caddy should delegate the TXT placement to.
-- Pre v1.3 there was only one (cloudflare) and the generator hardcoded
-- it, so every existing row gets 'cloudflare' as the default -- that
-- preserves behaviour exactly.
--
-- No CHECK constraint intentionally. The authoritative list lives in
-- internal/dnsproviders (Go catalogue) + migration 024's seed rows;
-- adding a provider must not require a writable_schema dance on hosts.
-- API layer validates the value against the catalogue AND against the
-- enabled flag of the matching dns_providers row.
ALTER TABLE hosts
    ADD COLUMN tls_dns_provider TEXT NOT NULL DEFAULT 'cloudflare';
