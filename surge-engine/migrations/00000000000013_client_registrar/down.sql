-- The old schema cannot express Platform clients; removing them cascades
-- their consents, codes, refresh tokens and audience approvals.
DELETE FROM surge.oauth_client WHERE registration_source = 'platform';

ALTER TABLE surge.oauth_client
    DROP CONSTRAINT oauth_client_platform_is_never_first_party,
    DROP CONSTRAINT oauth_client_platform_registrar,
    DROP CONSTRAINT oauth_client_registration_source;
ALTER TABLE surge.oauth_client
    ADD CONSTRAINT oauth_client_registration_source
        CHECK (registration_source IN ('admin', 'dynamic'));
ALTER TABLE surge.oauth_client DROP COLUMN registrar_service_id;
