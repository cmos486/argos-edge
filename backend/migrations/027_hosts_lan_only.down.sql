-- modernc/sqlite ships SQLite >= 3.49 so DROP COLUMN works directly;
-- no table-rebuild dance required.
ALTER TABLE hosts DROP COLUMN lan_only;
