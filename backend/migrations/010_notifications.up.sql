-- Phase 5: Notifications + alerts.
--
-- Channels are dispatch endpoints (webhook, email, telegram, browser_push).
-- config is a JSON blob whose shape depends on type; fields flagged as
-- "secret" in the notifications package get AES-GCM encrypted before
-- hitting this column.
--
-- Rules bind an event_type to a channel with optional host/severity
-- filters + throttle window for dedup.
--
-- Deliveries are the history table. rule_id and channel_id become NULL
-- if the rule/channel is later deleted so the historic row survives.
--
-- push_subscriptions stores per-browser Web Push endpoints for the
-- browser_push sender; one row per (user, endpoint).

CREATE TABLE notification_channels (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    name                   TEXT NOT NULL UNIQUE,
    type                   TEXT NOT NULL
        CHECK (type IN ('webhook', 'email', 'telegram', 'browser_push')),
    enabled                INTEGER NOT NULL DEFAULT 1,
    config                 TEXT NOT NULL DEFAULT '{}',
    template               TEXT NOT NULL DEFAULT '',
    rate_limit_per_minute  INTEGER NOT NULL DEFAULT 10,
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE notification_rules (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    name                     TEXT NOT NULL,
    channel_id               INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    event_type               TEXT NOT NULL,
    filter_host_ids          TEXT NOT NULL DEFAULT '',
    filter_severities        TEXT NOT NULL DEFAULT '',
    enabled                  INTEGER NOT NULL DEFAULT 1,
    throttle_window_seconds  INTEGER NOT NULL DEFAULT 0,
    created_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_notification_rules_event ON notification_rules(event_type, enabled);
CREATE INDEX idx_notification_rules_channel ON notification_rules(channel_id);

CREATE TABLE notification_deliveries (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id           INTEGER REFERENCES notification_rules(id) ON DELETE SET NULL,
    channel_id        INTEGER REFERENCES notification_channels(id) ON DELETE SET NULL,
    event_type        TEXT NOT NULL DEFAULT '',
    event_payload     TEXT NOT NULL DEFAULT '',
    rendered_payload  TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL
        CHECK (status IN ('pending', 'sent', 'failed', 'throttled', 'rate_limited')),
    error_message     TEXT NOT NULL DEFAULT '',
    attempts          INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at           TIMESTAMP
);

CREATE INDEX idx_notification_deliveries_created ON notification_deliveries(created_at DESC);
CREATE INDEX idx_notification_deliveries_status ON notification_deliveries(status, created_at DESC);
CREATE INDEX idx_notification_deliveries_event ON notification_deliveries(event_type, created_at DESC);
CREATE INDEX idx_notification_deliveries_channel ON notification_deliveries(channel_id, created_at DESC);

CREATE TABLE push_subscriptions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint    TEXT NOT NULL,
    p256dh_key  TEXT NOT NULL,
    auth_key    TEXT NOT NULL,
    user_agent  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, endpoint)
);

CREATE INDEX idx_push_subscriptions_user ON push_subscriptions(user_id);

-- Seed notification settings. VAPID keys are left blank; they will be
-- auto-generated on first boot and written back by the vapid helper.
INSERT INTO settings (key, value) VALUES
    ('notifications.vapid_public_key',    ''),
    ('notifications.vapid_private_key',   ''),
    ('notifications.vapid_contact_email', 'admin@example.com'),
    ('notifications.retention_days',      '30'),
    ('notifications.max_entries',         '100000');
