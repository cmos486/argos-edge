-- Rollback of 005: resurrect upstream_url + upstream_verify_tls on hosts,
-- reconstructing each value from the FIRST enabled target of the
-- associated target group (ordered by target.id). Hosts whose group has
-- more than one enabled target lose the extra targets: they existed
-- only after phase 2 so there is no phase-1 equivalent to map them to.
--
-- The WARN that the phase-2 spec asked for is not emitted here: pure
-- SQL has no logging primitive. Operators rolling back should first
-- run the query below to audit affected rows:
--
--     SELECT h.domain, COUNT(t.id) AS enabled_targets
--       FROM hosts h
--       JOIN targets t ON t.target_group_id = h.target_group_id
--      WHERE t.enabled = 1
--      GROUP BY h.id
--     HAVING enabled_targets > 1;

ALTER TABLE hosts ADD COLUMN upstream_url TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN upstream_verify_tls INTEGER NOT NULL DEFAULT 1;

UPDATE hosts
   SET upstream_url = (
       SELECT tg.protocol || '://' || t.host || ':' || t.port
         FROM targets t
         JOIN target_groups tg ON tg.id = t.target_group_id
        WHERE t.target_group_id = hosts.target_group_id
          AND t.enabled = 1
        ORDER BY t.id ASC
        LIMIT 1
   ),
       upstream_verify_tls = (
       SELECT tg.verify_tls
         FROM target_groups tg
        WHERE tg.id = hosts.target_group_id
   );

-- Rebuild hosts without target_group_id (SQLite cannot ALTER to drop
-- a NOT NULL FK cleanly, so we recreate and swap).
CREATE TABLE hosts_new (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    domain               TEXT NOT NULL UNIQUE,
    upstream_url         TEXT NOT NULL DEFAULT '',
    upstream_verify_tls  INTEGER NOT NULL DEFAULT 1,
    tls_mode             TEXT NOT NULL DEFAULT 'auto'
        CHECK (tls_mode IN ('auto', 'none')),
    tls_email            TEXT NOT NULL DEFAULT '',
    enabled              INTEGER NOT NULL DEFAULT 1,
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO hosts_new
    (id, domain, upstream_url, upstream_verify_tls,
     tls_mode, tls_email, enabled, created_at, updated_at)
SELECT id, domain, upstream_url, upstream_verify_tls,
       tls_mode, tls_email, enabled, created_at, updated_at
  FROM hosts;

DROP INDEX IF EXISTS idx_hosts_target_group_id;
DROP INDEX IF EXISTS idx_hosts_enabled;
DROP TABLE hosts;
ALTER TABLE hosts_new RENAME TO hosts;
CREATE INDEX idx_hosts_enabled ON hosts(enabled);
