-- Delegated registrations have no owning service and cannot be expressed in
-- the old schema; removing them cascades their grants.
DELETE FROM surge.oauth_resource WHERE registration_source = 'delegated';

DROP INDEX surge.idx_oauth_authorization_request_registration;
DROP INDEX surge.idx_oauth_refresh_registration;
DROP INDEX surge.idx_oauth_code_registration;
DROP INDEX surge.idx_oauth_consent_flow_registration;
DROP INDEX surge.idx_oauth_consent_registration;

ALTER TABLE surge.oauth_authorization_request
    DROP CONSTRAINT oauth_authorization_request_registration,
    DROP COLUMN registration_id;
ALTER TABLE surge.oauth_refresh_token
    DROP CONSTRAINT oauth_refresh_token_registration,
    DROP COLUMN registration_id;
ALTER TABLE surge.oauth_authorization_code
    DROP CONSTRAINT oauth_authorization_code_registration,
    DROP COLUMN registration_id;
ALTER TABLE surge.oauth_consent_flow
    DROP CONSTRAINT oauth_consent_flow_registration,
    DROP COLUMN registration_id;
ALTER TABLE surge.oauth_consent
    DROP CONSTRAINT oauth_consent_registration,
    DROP CONSTRAINT oauth_consent_pkey,
    DROP COLUMN registration_id,
    ADD CONSTRAINT oauth_consent_pkey PRIMARY KEY (client_id, identity_id, resource_uri);

DROP TABLE surge.oauth_client_audience;
ALTER TABLE surge.oauth_client DROP COLUMN audience_restricted;

DROP TRIGGER oauth_resource_identity_is_immutable ON surge.oauth_resource;
DROP FUNCTION surge.oauth_resource_identity_is_immutable();

ALTER TABLE surge.oauth_resource
    DROP CONSTRAINT oauth_resource_delegated_registrar,
    DROP CONSTRAINT oauth_resource_service_owner,
    DROP CONSTRAINT oauth_resource_registration_source,
    DROP CONSTRAINT oauth_resource_registration,
    DROP CONSTRAINT oauth_resource_uri_unique,
    DROP CONSTRAINT oauth_resource_pkey,
    ADD CONSTRAINT oauth_resource_pkey PRIMARY KEY (resource_uri),
    ALTER COLUMN service_id SET NOT NULL,
    DROP COLUMN dcr_enabled,
    DROP COLUMN allowed_cimd_client_ids,
    DROP COLUMN registrar_service_id,
    DROP COLUMN registration_source,
    DROP COLUMN id;

ALTER TABLE surge.oauth_consent
    ADD CONSTRAINT oauth_consent_resource_uri_fkey
        FOREIGN KEY (resource_uri) REFERENCES surge.oauth_resource (resource_uri) ON DELETE CASCADE;
