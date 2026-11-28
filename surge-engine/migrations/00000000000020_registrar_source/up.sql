-- A client created by a service holding `oauth_client_register` is a
-- 'registrar' client. Surge names the role, not any service that holds it,
-- so the source value and its constraints are renamed from their original
-- spelling (migration 13).
ALTER TABLE surge.oauth_client
    DROP CONSTRAINT oauth_client_platform_is_never_first_party,
    DROP CONSTRAINT oauth_client_platform_registrar,
    DROP CONSTRAINT oauth_client_registration_source;

UPDATE surge.oauth_client
SET registration_source = 'registrar'
WHERE registration_source = 'platform';

ALTER TABLE surge.oauth_client
    ADD CONSTRAINT oauth_client_registration_source
        CHECK (registration_source IN ('admin', 'dynamic', 'registrar', 'cimd')),
    ADD CONSTRAINT oauth_client_registrar_has_registrar
        CHECK ((registration_source = 'registrar') = (registrar_service_id IS NOT NULL)),
    ADD CONSTRAINT oauth_client_registrar_is_never_first_party
        CHECK (NOT (registration_source = 'registrar' AND first_party));
