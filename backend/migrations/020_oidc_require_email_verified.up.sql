-- Opt-in policy: when set to 'true' the OIDC callback rejects any
-- identity whose id_token either lacks the email_verified claim or
-- sends it false. Default stays 'false' so panels upgrading from
-- v1.0 keep their current auto-provision behaviour; operators running
-- against Google/Microsoft/Keycloak/etc flip it on from the UI.
INSERT INTO settings (key, value) VALUES
    ('oidc.require_email_verified', 'false');
