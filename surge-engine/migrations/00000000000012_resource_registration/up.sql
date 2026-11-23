-- Protected resources become registrations with an identity of their own.
--
-- Until now the canonical URI was the primary key, and the codes, consent
-- flows and refresh tokens issued for it named it only as text. Deleting and
-- re-registering a URI therefore silently handed every outstanding grant to
-- whichever service registered it next. From here on each registration has
-- an immutable `id`, every grant names that id, and a grant can only ever be
-- redeemed against the registration instance it was issued for. The URI stays
-- what clients, the API and the JWT `aud` claim speak.

-- 1. The registration row.
ALTER TABLE surge.oauth_resource
    ADD COLUMN id UUID NOT NULL DEFAULT gen_random_uuid(),
    -- 'service': a first-party resource server owned by `service_id`, which
    -- is also the service allowed to introspect its tokens.
    -- 'delegated': registered on a developer's behalf; owned by no service.
    ADD COLUMN registration_source TEXT NOT NULL DEFAULT 'service',
    -- The authenticated service that created the registration. NULL means
    -- unknown: every row that predates this migration, and registrations made
    -- by an operator through the CLI. Deliberately not a foreign key, so the
    -- provenance survives the registrar's deletion instead of collapsing
    -- into "unknown".
    ADD COLUMN registrar_service_id UUID,
    -- Exact CIMD client-ID URLs permitted to obtain tokens for this resource.
    ADD COLUMN allowed_cimd_client_ids TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    -- Whether dynamically registered clients may use this resource without an
    -- explicit audience binding.
    ADD COLUMN dcr_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- The backfill needed the default; new rows must say what they are.
ALTER TABLE surge.oauth_resource ALTER COLUMN registration_source DROP DEFAULT;
ALTER TABLE surge.oauth_resource ALTER COLUMN service_id DROP NOT NULL;

ALTER TABLE surge.oauth_consent DROP CONSTRAINT oauth_consent_resource_uri_fkey;
ALTER TABLE surge.oauth_resource DROP CONSTRAINT oauth_resource_pkey;
ALTER TABLE surge.oauth_resource ADD CONSTRAINT oauth_resource_pkey PRIMARY KEY (id);
ALTER TABLE surge.oauth_resource
    ADD CONSTRAINT oauth_resource_uri_unique UNIQUE (resource_uri),
    -- Target of the grant tables' composite foreign keys: a grant's id and
    -- its URI must name the same registration.
    ADD CONSTRAINT oauth_resource_registration UNIQUE (id, resource_uri),
    ADD CONSTRAINT oauth_resource_registration_source
        CHECK (registration_source IN ('service', 'delegated')),
    -- Introspection authority follows `service_id`, so only a service
    -- registration may have one, and every service registration does.
    ADD CONSTRAINT oauth_resource_service_owner
        CHECK ((registration_source = 'service') = (service_id IS NOT NULL)),
    ADD CONSTRAINT oauth_resource_delegated_registrar
        CHECK (registration_source <> 'delegated' OR registrar_service_id IS NOT NULL);

CREATE FUNCTION surge.oauth_resource_identity_is_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.resource_uri IS DISTINCT FROM OLD.resource_uri
        OR NEW.registration_source IS DISTINCT FROM OLD.registration_source
        OR NEW.registrar_service_id IS DISTINCT FROM OLD.registrar_service_id
    THEN
        RAISE EXCEPTION 'oauth_resource identity, URI, source and registrar are immutable'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER oauth_resource_identity_is_immutable
    BEFORE UPDATE ON surge.oauth_resource
    FOR EACH ROW EXECUTE FUNCTION surge.oauth_resource_identity_is_immutable();

-- 2. Client audience approvals, held against registration ids so that
-- re-registering a URI can never resurrect an approval given to its
-- predecessor. `audience_restricted = FALSE` is the API's `audiences: null`
-- (no explicit list); TRUE with no rows is an empty list.
ALTER TABLE surge.oauth_client
    ADD COLUMN audience_restricted BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE surge.oauth_client_audience (
    client_id       TEXT NOT NULL REFERENCES surge.oauth_client(client_id) ON DELETE CASCADE,
    registration_id UUID NOT NULL REFERENCES surge.oauth_resource(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, registration_id)
);

CREATE INDEX idx_oauth_client_audience_registration
    ON surge.oauth_client_audience (registration_id);

-- 3. Bind every grant to its registration.
--
-- Consents were already cascaded by a foreign key on the URI, so each one
-- belongs to the registration that holds the URI today.
--
-- Flows, codes and refresh tokens were not. One created at or before the
-- current registration's `created_at` may have been issued for a deleted
-- predecessor with a different owner, and one whose URI is no longer
-- registered belongs to nobody. Those cannot be attributed honestly, so they
-- are dropped and the client has to authorize again. A refresh family is
-- judged by its first token, since rotation carries the grant forward.
ALTER TABLE surge.oauth_consent ADD COLUMN registration_id UUID;
UPDATE surge.oauth_consent c
   SET registration_id = r.id
  FROM surge.oauth_resource r
 WHERE r.resource_uri = c.resource_uri;
DELETE FROM surge.oauth_consent WHERE registration_id IS NULL;

ALTER TABLE surge.oauth_consent_flow ADD COLUMN registration_id UUID;
UPDATE surge.oauth_consent_flow f
   SET registration_id = r.id
  FROM surge.oauth_resource r
 WHERE r.resource_uri = f.resource_uri
   AND f.created_at > r.created_at;
DELETE FROM surge.oauth_consent_flow WHERE registration_id IS NULL;

ALTER TABLE surge.oauth_authorization_code ADD COLUMN registration_id UUID;
UPDATE surge.oauth_authorization_code c
   SET registration_id = r.id
  FROM surge.oauth_resource r
 WHERE r.resource_uri = c.resource_uri
   AND c.issued_at > r.created_at;
DELETE FROM surge.oauth_authorization_code WHERE registration_id IS NULL;

ALTER TABLE surge.oauth_refresh_token ADD COLUMN registration_id UUID;
WITH family AS (
    SELECT family_id, min(resource_uri) AS resource_uri, min(issued_at) AS born
      FROM surge.oauth_refresh_token
     GROUP BY family_id
    HAVING count(DISTINCT resource_uri) = 1
)
UPDATE surge.oauth_refresh_token t
   SET registration_id = r.id
  FROM family f
  JOIN surge.oauth_resource r ON r.resource_uri = f.resource_uri
 WHERE t.family_id = f.family_id
   AND f.born > r.created_at;
DELETE FROM surge.oauth_refresh_token WHERE registration_id IS NULL;

-- A pending account choice replays the whole authorize request later, so it
-- is bound the same way. Its creation time is its expiry minus the fixed
-- ten-minute lifetime.
ALTER TABLE surge.oauth_authorization_request ADD COLUMN registration_id UUID;
UPDATE surge.oauth_authorization_request q
   SET registration_id = r.id
  FROM surge.oauth_resource r
 WHERE r.resource_uri = q.request->>'resource'
   AND q.expires_at - INTERVAL '10 minutes' > r.created_at;
DELETE FROM surge.oauth_authorization_request WHERE registration_id IS NULL;

ALTER TABLE surge.oauth_consent
    ALTER COLUMN registration_id SET NOT NULL,
    DROP CONSTRAINT oauth_consent_pkey,
    ADD CONSTRAINT oauth_consent_pkey PRIMARY KEY (client_id, identity_id, registration_id),
    ADD CONSTRAINT oauth_consent_registration
        FOREIGN KEY (registration_id, resource_uri)
        REFERENCES surge.oauth_resource (id, resource_uri) ON DELETE CASCADE;

ALTER TABLE surge.oauth_consent_flow
    ALTER COLUMN registration_id SET NOT NULL,
    ADD CONSTRAINT oauth_consent_flow_registration
        FOREIGN KEY (registration_id, resource_uri)
        REFERENCES surge.oauth_resource (id, resource_uri) ON DELETE CASCADE;

ALTER TABLE surge.oauth_authorization_code
    ALTER COLUMN registration_id SET NOT NULL,
    ADD CONSTRAINT oauth_authorization_code_registration
        FOREIGN KEY (registration_id, resource_uri)
        REFERENCES surge.oauth_resource (id, resource_uri) ON DELETE CASCADE;

ALTER TABLE surge.oauth_refresh_token
    ALTER COLUMN registration_id SET NOT NULL,
    ADD CONSTRAINT oauth_refresh_token_registration
        FOREIGN KEY (registration_id, resource_uri)
        REFERENCES surge.oauth_resource (id, resource_uri) ON DELETE CASCADE;

ALTER TABLE surge.oauth_authorization_request
    ALTER COLUMN registration_id SET NOT NULL,
    ADD CONSTRAINT oauth_authorization_request_registration
        FOREIGN KEY (registration_id)
        REFERENCES surge.oauth_resource (id) ON DELETE CASCADE;

CREATE INDEX idx_oauth_consent_registration ON surge.oauth_consent (registration_id);
CREATE INDEX idx_oauth_consent_flow_registration ON surge.oauth_consent_flow (registration_id);
CREATE INDEX idx_oauth_code_registration ON surge.oauth_authorization_code (registration_id);
CREATE INDEX idx_oauth_refresh_registration ON surge.oauth_refresh_token (registration_id);
CREATE INDEX idx_oauth_authorization_request_registration
    ON surge.oauth_authorization_request (registration_id);
