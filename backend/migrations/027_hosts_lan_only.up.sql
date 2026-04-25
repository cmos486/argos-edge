-- v1.3.18: hosts.lan_only -- when true the Caddy emit wraps the
-- per-host route in a remote_ip matcher that accepts only RFC 1918
-- + loopback + ULA sources, and serves a 403 to anything else.
-- Default false to preserve pre-v1.3.18 behaviour for every existing
-- host on upgrade. Operators flip the toggle per-host via the Edit
-- Host modal -- typical use is admin panels exposed via public DNS
-- + valid TLS but reachable only from the LAN / VPN.
ALTER TABLE hosts
    ADD COLUMN lan_only INTEGER NOT NULL DEFAULT 0;
