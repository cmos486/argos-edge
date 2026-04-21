-- Rollback the v1.3 DNS providers catalogue. Hosts may still reference
-- a provider by name in hosts.tls_dns_provider; migration 025 is the
-- counterpart column and must be rolled back BEFORE 024 in the normal
-- sequence (the runner handles order). Any DB-stored credentials are
-- lost on down -- operators must re-populate CLOUDFLARE_API_TOKEN in
-- .env if they relied on the env-import flow.
DROP INDEX IF EXISTS idx_dns_providers_enabled;
DROP TABLE IF EXISTS dns_providers;
