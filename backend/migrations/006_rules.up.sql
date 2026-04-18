-- Listener rules, AWS-ALB style. Each host owns an ordered list of rules
-- that may override its default target group. At request time Caddy
-- evaluates rules in priority order (lower first); the first match wins
-- and is terminal. When no rule matches, the host's default target_group
-- catches the request.
--
-- Rules are stored with opaque JSON blobs for matchers_config and
-- action_config. The schema keeps TEXT CHECK constraints at row level
-- only for action_type, which the validators + caddycfg rely on. Full
-- structural validation (matcher kinds, required fields per action)
-- lives in internal/models so the DB stays agnostic about new matcher
-- or action types introduced later.
CREATE TABLE rules (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id          INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    priority         INTEGER NOT NULL,
    name             TEXT NOT NULL DEFAULT '',
    enabled          INTEGER NOT NULL DEFAULT 1,
    action_type      TEXT NOT NULL
        CHECK (action_type IN ('forward','redirect','fixed_response','block','rewrite')),
    action_config    TEXT NOT NULL DEFAULT '{}',    -- JSON, shape per action_type
    matchers_config  TEXT NOT NULL DEFAULT '[]',    -- JSON array of {type, config}
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (host_id, priority),
    CHECK (priority BETWEEN 1 AND 50000)
);

CREATE INDEX idx_rules_host_priority ON rules(host_id, priority);
CREATE INDEX idx_rules_enabled       ON rules(enabled);
