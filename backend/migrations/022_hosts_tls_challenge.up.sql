-- Per-host ACME challenge selector. Three supported challenge types:
--   'dns'      -- DNS-01 via the caddy-dns Cloudflare provider (pre-022
--                 behaviour; the default for every existing row).
--   'http'     -- HTTP-01 over port 80. Requires :80 reachable from the
--                 Let's Encrypt validation servers. Cannot issue
--                 wildcard certs.
--   'tls-alpn' -- TLS-ALPN-01 over port 443. Same reachability
--                 requirement but uses the existing TLS listener.
--                 Cannot issue wildcard certs.
--
-- The field is independent of tls_mode: tls_mode=none continues to
-- ignore the challenge (no cert requested at all). tls_mode=auto
-- reads this column to decide which stanza to emit inside
-- acme.Challenges on the next reconcile.

ALTER TABLE hosts ADD COLUMN tls_challenge TEXT NOT NULL DEFAULT 'dns'
    CHECK (tls_challenge IN ('dns', 'http', 'tls-alpn'));
