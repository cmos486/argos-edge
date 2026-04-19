-- Phase 7: CrowdSec LAPI wiring.
--
-- Seeds settings used by internal/crowdsec. The three secret keys
-- (bouncer_api_key, machine_user, machine_password) are stored via
-- the existing settings table. The values start empty; the operator
-- runs the one-time setup documented in README to populate them.
-- When the client sees an empty key it reports "not_configured" to
-- the UI rather than banging on the LAPI.
--
-- No table is added: decisions live in CrowdSec; argos just queries.

INSERT INTO settings (key, value) VALUES
    ('crowdsec.enabled',              'true'),
    ('crowdsec.lapi_url',             'http://crowdsec:8081'),
    ('crowdsec.poll_interval_seconds','15'),
    ('crowdsec.bouncer_api_key',      ''),
    ('crowdsec.machine_user',         ''),
    ('crowdsec.machine_password',     '');
