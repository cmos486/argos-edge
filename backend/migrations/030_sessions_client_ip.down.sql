-- SQLite ALTER TABLE DROP COLUMN landed in 3.35 (2021); modernc/sqlite
-- supports it. Drop both client_ip and xff_chain.
ALTER TABLE sessions DROP COLUMN client_ip;
ALTER TABLE sessions DROP COLUMN xff_chain;
