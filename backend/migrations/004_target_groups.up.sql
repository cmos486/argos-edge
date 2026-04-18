-- Target groups are an AWS-style indirection between a Host (public
-- domain) and a set of backend servers. A Host selects a target group;
-- the target group owns the protocol, TLS verification policy, load
-- balancing algorithm and health-check configuration shared across all
-- of its targets. Targets are plain host:port endpoints.
--
-- expect_status is stored as TEXT so operators can express CSV lists
-- ("200,301,302") or ranges ("200-299") instead of a single int;
-- caddycfg's expectstatus helper parses it into the JSON Caddy wants.
CREATE TABLE target_groups (
    id                                INTEGER PRIMARY KEY AUTOINCREMENT,
    name                              TEXT NOT NULL UNIQUE,
    protocol                          TEXT NOT NULL DEFAULT 'http'
        CHECK (protocol IN ('http', 'https')),
    verify_tls                        INTEGER NOT NULL DEFAULT 1,
    algorithm                         TEXT NOT NULL DEFAULT 'round_robin'
        CHECK (algorithm IN ('round_robin', 'least_conn', 'ip_hash', 'random')),
    health_check_enabled              INTEGER NOT NULL DEFAULT 0,
    health_check_path                 TEXT    NOT NULL DEFAULT '/',
    health_check_method               TEXT    NOT NULL DEFAULT 'GET'
        CHECK (health_check_method IN ('GET', 'HEAD', 'POST')),
    health_check_expect_status        TEXT    NOT NULL DEFAULT '200',
    health_check_interval_seconds     INTEGER NOT NULL DEFAULT 30,
    health_check_timeout_seconds      INTEGER NOT NULL DEFAULT 5,
    health_check_fails_to_unhealthy   INTEGER NOT NULL DEFAULT 2,
    health_check_passes_to_healthy    INTEGER NOT NULL DEFAULT 2,
    created_at                        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE targets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_group_id INTEGER NOT NULL REFERENCES target_groups(id) ON DELETE CASCADE,
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL,
    weight          INTEGER NOT NULL DEFAULT 1,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (target_group_id, host, port)
);

CREATE INDEX idx_targets_group_id ON targets(target_group_id);
CREATE INDEX idx_targets_enabled  ON targets(enabled);
