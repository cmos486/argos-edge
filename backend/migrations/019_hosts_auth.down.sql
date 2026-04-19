-- SQLite pre-3.35 has no DROP COLUMN; modernc driver ships 3.49 so
-- we rely on it here. Simpler than a full table rebuild.
ALTER TABLE hosts DROP COLUMN auth_required;
