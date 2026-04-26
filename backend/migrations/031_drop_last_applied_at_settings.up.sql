-- v1.3.27: drop the deprecated mark-applied settings keys.
--
-- Until v1.3.26 the panel surfaced "Mark as applied" buttons on
-- the Scenarios + AppSec tuning tabs and recorded
-- appsec.scenarios.last_applied_at + appsec.tuning.last_applied_at
-- in the settings k/v store. PendingReloadBadge derived its
-- pending state from last_modified > last_applied -- an
-- operator-trust signal that did not catch drift between the
-- panel's recorded intent and the running CrowdSec state.
--
-- v1.3.27 replaces the operator-trust model with a real drift
-- detector that compares the panel sentinels against the actual
-- /crowdsec-state mount every 60s. The mark-applied API endpoints
-- and their settings rows are removed.
--
-- Idempotent. DELETE on missing keys is a no-op in SQLite.
DELETE FROM settings WHERE key = 'appsec.scenarios.last_applied_at';
DELETE FROM settings WHERE key = 'appsec.tuning.last_applied_at';
