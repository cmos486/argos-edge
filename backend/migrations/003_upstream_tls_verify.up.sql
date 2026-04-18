-- Upstream certificate verification flag. Only meaningful when
-- upstream_url is https://. Default 1 (verify) because the panel should
-- nudge operators towards valid chains and force an opt-out for the
-- self-signed / SNI-mismatch cases common in homelab backends
-- (Home Assistant, Proxmox, Synology, etc).
ALTER TABLE hosts
    ADD COLUMN upstream_verify_tls INTEGER NOT NULL DEFAULT 1;
