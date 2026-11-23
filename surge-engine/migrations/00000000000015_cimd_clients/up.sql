-- Clients identified by a client-ID metadata document (CIMD).
--
-- The client ID is the HTTPS URL of a document the client itself publishes.
-- Surge fetches and validates that document when an authorization request
-- needs it, and writes one row here only when a consent flow is created, so
-- the grant tables (consent, flows, codes, refresh tokens) can reference the
-- client like any other. The row carries the last validated document; every
-- later stage (code redemption, refresh) uses the row and the resource's
-- current policy and never fetches.
--
-- The invariants below are the ones the rest of the design relies on, stated
-- where a future code path cannot forget them.
ALTER TABLE surge.oauth_client DROP CONSTRAINT oauth_client_registration_source;
ALTER TABLE surge.oauth_client
    ADD CONSTRAINT oauth_client_registration_source
        CHECK (registration_source IN ('admin', 'dynamic', 'platform', 'cimd')),
    -- A self-declared client can never skip consent.
    ADD CONSTRAINT oauth_client_cimd_is_never_first_party
        CHECK (NOT (registration_source = 'cimd' AND first_party)),
    -- Confidential CIMD authentication is out of scope: a CIMD client is
    -- public, so it has no secret and authenticates with `none`.
    ADD CONSTRAINT oauth_client_cimd_is_public
        CHECK (registration_source <> 'cimd'
               OR (client_secret_hash IS NULL AND token_endpoint_auth_method = 'none')),
    -- The identifier namespace: an HTTPS URL is a CIMD client and nothing
    -- else is, so no other source can mint an ID that eligibility would
    -- treat as a document URL (or the reverse).
    ADD CONSTRAINT oauth_client_cimd_id_is_url
        CHECK ((registration_source = 'cimd') = (client_id LIKE 'https://%'));
