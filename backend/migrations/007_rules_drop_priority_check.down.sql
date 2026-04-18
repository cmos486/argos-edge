-- Re-add the priority BETWEEN 1 AND 50000 CHECK. Note this requires
-- every current row to fit; reorder parking values would fail a
-- subsequent migration round-trip while the table is in flight.
CREATE TABLE rules_old (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id          INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    priority         INTEGER NOT NULL,
    name             TEXT NOT NULL DEFAULT '',
    enabled          INTEGER NOT NULL DEFAULT 1,
    action_type      TEXT NOT NULL
        CHECK (action_type IN ('forward','redirect','fixed_response','block','rewrite')),
    action_config    TEXT NOT NULL DEFAULT '{}',
    matchers_config  TEXT NOT NULL DEFAULT '[]',
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (host_id, priority),
    CHECK (priority BETWEEN 1 AND 50000)
);

INSERT INTO rules_old
    (id, host_id, priority, name, enabled, action_type,
     action_config, matchers_config, created_at, updated_at)
SELECT id, host_id, priority, name, enabled, action_type,
       action_config, matchers_config, created_at, updated_at
  FROM rules;

DROP INDEX IF EXISTS idx_rules_enabled;
DROP INDEX IF EXISTS idx_rules_host_priority;
DROP TABLE rules;
ALTER TABLE rules_old RENAME TO rules;
CREATE INDEX idx_rules_host_priority ON rules(host_id, priority);
CREATE INDEX idx_rules_enabled       ON rules(enabled);
