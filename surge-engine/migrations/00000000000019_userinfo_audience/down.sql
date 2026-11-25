DELETE FROM surge.oauth_resource WHERE registration_source = 'userinfo';

ALTER TABLE surge.oauth_resource
    DROP CONSTRAINT oauth_resource_userinfo_audience,
    DROP CONSTRAINT oauth_resource_registration_source,
    ADD CONSTRAINT oauth_resource_registration_source
        CHECK (registration_source IN ('service', 'delegated'));
