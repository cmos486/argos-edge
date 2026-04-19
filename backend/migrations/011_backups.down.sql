DELETE FROM settings WHERE key LIKE 'backup.%';

DROP INDEX IF EXISTS idx_backups_created_at;
DROP TABLE IF EXISTS backups;
