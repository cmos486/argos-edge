-- SQLite 3.35+ supports ALTER TABLE DROP COLUMN directly; modernc.org/sqlite
-- is well past that threshold (the same runtime the panel binary uses).
ALTER TABLE hosts DROP COLUMN tls_dns_provider;
