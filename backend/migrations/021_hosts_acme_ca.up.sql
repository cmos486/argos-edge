-- Per-host ACME CA URL override. Empty string = fall back to the
-- acme.ca_url global setting (or Caddy's Let's Encrypt production
-- default). Env var ARGOS_ACME_CA_URL still trumps both at reconcile
-- time (ops-level escape hatch).
--
-- Default '' preserves pre-021 behaviour: every host stays on the
-- previously-implicit LE production CA.

ALTER TABLE hosts ADD COLUMN tls_acme_ca_url TEXT NOT NULL DEFAULT '';
