-- v1.3.19: hosts.true_detect_mode -- when true, AppSec WAF alerts
-- originating from this host's traffic do NOT feed scenario-based
-- bans. Useful for hosts whose legitimate traffic triggers
-- false positives (socket.io polling apps, monitoring dashboards,
-- hot-reload dev servers). Inline AppSec blocking still applies if
-- the host's target group is in block mode -- the toggle only
-- intercepts the alert -> scenario -> LAPI-decision pipeline at
-- the profiles.yaml stage so the bouncer never sees a ban for the
-- host's source IPs.
--
-- Default 0 to preserve pre-v1.3.19 behaviour for every existing
-- host on upgrade. Operators flip the toggle per-host via the
-- Edit Host modal.
ALTER TABLE hosts
    ADD COLUMN true_detect_mode INTEGER NOT NULL DEFAULT 0;

-- v1.3.19: security_whitelist persists manual whitelist entries
-- created via the panel's "Whitelist my IP permanently" action
-- (the button next to the self-block banner). Each entry maps to
-- a row in /etc/crowdsec/parsers/s02-enrich/argos-whitelist.yaml
-- written by setup-appsec.sh on its next run. System ranges
-- (RFC 1918 / loopback / ULA) are not stored here -- they are
-- emitted unconditionally by the script.
--
-- v1.3.20+ will surface a full Whitelist tab; v1.3.19 only writes
-- one entry per operator self-rescue, so the table is intentionally
-- small (no source/origin tracking, no audit columns -- those
-- arrive with the audit-log table in v1.3.20).
CREATE TABLE security_whitelist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT NOT NULL CHECK (scope IN ('ip', 'range')),
    value       TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scope, value)
);
