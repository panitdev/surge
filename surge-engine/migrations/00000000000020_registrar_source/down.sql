-- Restores the source value and constraint names of migration 13.
ALTER TABLE surge.oauth_client
    DROP CONSTRAINT oauth_client_registrar_is_never_first_party,
    DROP CONSTRAINT oauth_client_registrar_has_registrar,
    DROP CONSTRAINT oauth_client_registration_source;

UPDATE surge.oauth_client
SET registration_source = 'platform'
WHERE registration_source = 'registrar';

ALTER TABLE surge.oauth_client
    ADD CONSTRAINT oauth_client_registration_source
        CHECK (registration_source IN ('admin', 'dynamic', 'platform', 'cimd')),
    ADD CONSTRAINT oauth_client_platform_registrar
        CHECK ((registration_source = 'platform') = (registrar_service_id IS NOT NULL)),
    ADD CONSTRAINT oauth_client_platform_is_never_first_party
        CHECK (NOT (registration_source = 'platform' AND first_party));
