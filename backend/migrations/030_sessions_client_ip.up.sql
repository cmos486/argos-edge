-- v1.3.23: capture client_ip + xff_chain on session creation so
-- the SelfBlockBanner v2 multi-IP detection can enumerate every
-- IP the operator's active sessions are tied to.
--
-- Background: v1.3.19's banner only saw the resolved client IP
-- of the in-flight request. An operator hitting the panel via
-- LAN never saw their public WAN IP, so a CrowdSec ban targeting
-- the public IP went unnoticed. v1.3.23's banner reads
-- session.client_ip across active sessions, plus a panel-side
-- ipify poll for the public IP, and probes LAPI for each.
--
-- Both columns are NULL-allowed: existing rows from pre-v1.3.23
-- sessions degrade gracefully (the banner just doesn't see those
-- session IPs). New logins populate them via the auth handler.
ALTER TABLE sessions ADD COLUMN client_ip TEXT;
ALTER TABLE sessions ADD COLUMN xff_chain TEXT;
