-- modernc/sqlite ships SQLite >= 3.49 so DROP COLUMN works directly;
-- no table-rebuild dance required.
ALTER TABLE hosts DROP COLUMN true_detect_mode;
DROP TABLE IF EXISTS security_whitelist;
