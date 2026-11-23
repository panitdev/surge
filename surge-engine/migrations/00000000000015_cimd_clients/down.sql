DELETE FROM surge.oauth_client WHERE registration_source = 'cimd';
ALTER TABLE surge.oauth_client
    DROP CONSTRAINT oauth_client_cimd_id_is_url,
    DROP CONSTRAINT oauth_client_cimd_is_public,
    DROP CONSTRAINT oauth_client_cimd_is_never_first_party,
    DROP CONSTRAINT oauth_client_registration_source;
ALTER TABLE surge.oauth_client
    ADD CONSTRAINT oauth_client_registration_source
        CHECK (registration_source IN ('admin', 'dynamic', 'platform'));
