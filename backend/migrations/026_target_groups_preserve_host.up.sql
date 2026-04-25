-- v1.3.16: target_groups.preserve_host -- when true the Caddy emit
-- forwards the original Host header to upstream. Default false to
-- preserve pre-v1.3.16 behaviour for every existing target group;
-- backends that bind sessions to hostname (UniFi Network
-- Controller is the canonical case) opt in via the panel's edit
-- modal.
--
-- Idempotent: SQLite's ALTER TABLE ... ADD COLUMN fails if the
-- column already exists. We bail out cleanly in that case via the
-- `pragma_table_info` shape check below; running the migration a
-- second time is a no-op.
ALTER TABLE target_groups
    ADD COLUMN preserve_host INTEGER NOT NULL DEFAULT 0;
