-- Drop the priority BETWEEN 1 AND 50000 CHECK from rules.
--
-- Reason: ReorderRules parks rows at priority = id + 100000 while
-- shuffling so the UNIQUE(host_id, priority) constraint cannot collide
-- mid-transaction. The CHECK made those intermediate values illegal
-- and any reorder failed with "CHECK constraint failed".
--
-- Bounds enforcement is still done at the API edge
-- (models.Rule.Validate, 1-50000); the DB layer only needs the UNIQUE
-- and the action_type CHECK, which are preserved below.

CREATE TABLE rules_new (
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
    UNIQUE (host_id, priority)
);

INSERT INTO rules_new
    (id, host_id, priority, name, enabled, action_type,
     action_config, matchers_config, created_at, updated_at)
SELECT id, host_id, priority, name, enabled, action_type,
       action_config, matchers_config, created_at, updated_at
  FROM rules;

DROP INDEX IF EXISTS idx_rules_enabled;
DROP INDEX IF EXISTS idx_rules_host_priority;
DROP TABLE rules;
ALTER TABLE rules_new RENAME TO rules;
CREATE INDEX idx_rules_host_priority ON rules(host_id, priority);
CREATE INDEX idx_rules_enabled       ON rules(enabled);
