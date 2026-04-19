-- CrowdSec AppSec (WAF inline) runtime mode + change-audit metadata.
--
-- Three valid values for appsec.mode:
--   detect    default. Caddy forwards to the detect listener (7423);
--             rules match, alerts fire, request goes through.
--   block     Caddy forwards to the block listener (7422); rules that
--             match in-band send the bouncer 403.
--   disabled  Caddy omits appsec_url entirely; no WAF round-trip, no
--             hits, no overhead.
--
-- The reconciler regenerates the Caddy config from these settings on
-- every change (POST /load to the admin API, no container restart).
--
-- The *_last_* rows exist so the /api/appsec/status endpoint can show
-- who and when flipped the switch without having to search the audit
-- log. They are nullable because fresh installs have no prior change.

INSERT INTO settings (key, value) VALUES
    ('appsec.mode',                 'detect'),
    ('appsec.last_mode_change_at',  ''),
    ('appsec.last_mode_change_by',  '');
