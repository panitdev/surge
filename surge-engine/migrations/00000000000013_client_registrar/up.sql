-- A client registered by a Platform service through the delegated client
-- grant. 'platform' clients are third-party and untrusted, like dynamic
-- ones: their name and logo are supplied by a developer, not verified.
-- Unlike dynamic clients they are never swept for lack of use; the
-- registrar manages their lifecycle.
ALTER TABLE surge.oauth_client
    -- The authenticated service that registered the client. NULL for admin
    -- and dynamic clients. Not a foreign key, so provenance survives the
    -- registrar's deletion (the same choice as oauth_resource).
    ADD COLUMN registrar_service_id UUID;

ALTER TABLE surge.oauth_client DROP CONSTRAINT oauth_client_registration_source;
ALTER TABLE surge.oauth_client
    ADD CONSTRAINT oauth_client_registration_source
        CHECK (registration_source IN ('admin', 'dynamic', 'platform')),
    ADD CONSTRAINT oauth_client_platform_registrar
        CHECK ((registration_source = 'platform') = (registrar_service_id IS NOT NULL)),
    ADD CONSTRAINT oauth_client_platform_is_never_first_party
        CHECK (NOT (registration_source = 'platform' AND first_party));
