DELETE FROM settings WHERE key LIKE 'notifications.%';

DROP INDEX IF EXISTS idx_push_subscriptions_user;
DROP INDEX IF EXISTS idx_notification_deliveries_channel;
DROP INDEX IF EXISTS idx_notification_deliveries_event;
DROP INDEX IF EXISTS idx_notification_deliveries_status;
DROP INDEX IF EXISTS idx_notification_deliveries_created;
DROP INDEX IF EXISTS idx_notification_rules_channel;
DROP INDEX IF EXISTS idx_notification_rules_event;

DROP TABLE IF EXISTS push_subscriptions;
DROP TABLE IF EXISTS notification_deliveries;
DROP TABLE IF EXISTS notification_rules;
DROP TABLE IF EXISTS notification_channels;
