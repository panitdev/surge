ALTER TABLE surge.oauth_resource
    DROP CONSTRAINT oauth_resource_registration_source,
    ADD CONSTRAINT oauth_resource_registration_source
        CHECK (registration_source IN ('service', 'delegated', 'userinfo')),
    ADD CONSTRAINT oauth_resource_userinfo_audience
        CHECK ((registration_source = 'userinfo') = (resource_uri = 'urn:surge:oauth:userinfo'));

INSERT INTO surge.oauth_resource (resource_uri, registration_source, scope_descriptions)
VALUES ('urn:surge:oauth:userinfo', 'userinfo', '{"openid": "Sign in with your Surge account"}');
