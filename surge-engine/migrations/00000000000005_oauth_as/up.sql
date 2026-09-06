-- Surge as a native OAuth 2.1 / OIDC authorization server (internal/oauth-as.md).
--
-- The reason this lives in the engine rather than behind a separate service:
-- what an OAuth token must be scoped to is a *resource server*, and Surge
-- already owns the registry of those (`surge.service`). Consent, revocation
-- and audience validation each need the client half and the identity/service
-- half in one query; splitting them across two datastores is what makes an
-- external AS painful.

-- A registered OAuth client. `client_id` is a public identifier (aeg_cid_…);
-- a NULL `client_secret_hash` means a public client, which is the normal case
-- for MCP/native clients and is safe only because PKCE is mandatory.
CREATE TABLE surge.oauth_client (
    client_id                  TEXT PRIMARY KEY,
    client_secret_hash         BYTEA,
    client_name                TEXT        NOT NULL,
    client_uri                 TEXT,
    logo_uri                   TEXT,
    -- Exact match only. No wildcards, ever: a pattern here is an open
    -- redirect with extra steps.
    redirect_uris              TEXT[]      NOT NULL,
    grant_types                TEXT[]      NOT NULL DEFAULT ARRAY['authorization_code','refresh_token'],
    -- The maximum this client may ever be granted. Narrowed further at
    -- authorize time by what the resource itself defines.
    scopes                     TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    token_endpoint_auth_method TEXT        NOT NULL DEFAULT 'none',
    -- 'admin' | 'dynamic'. Immutable after insert: a dynamically registered
    -- client can never promote itself.
    registration_source        TEXT        NOT NULL DEFAULT 'admin',
    -- Skips the consent screen. Admin-registered only, enforced in the engine.
    first_party                BOOLEAN     NOT NULL DEFAULT FALSE,
    trust_state                TEXT        NOT NULL DEFAULT 'untrusted',
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at               TIMESTAMPTZ,
    revoked_at                 TIMESTAMPTZ,
    CONSTRAINT oauth_client_registration_source
        CHECK (registration_source IN ('admin', 'dynamic')),
    CONSTRAINT oauth_client_trust_state
        CHECK (trust_state IN ('untrusted', 'trusted')),
    -- The invariant the whole DCR abuse story rests on, stated where it
    -- cannot be forgotten by a future code path.
    CONSTRAINT oauth_client_dynamic_is_never_first_party
        CHECK (NOT (registration_source = 'dynamic' AND first_party))
);

-- The audience registry: the piece that does not exist when an external AS
-- owns clients and Surge owns services. A `resource` parameter is valid iff
-- it resolves here, and the service owning the row is the one that may
-- introspect tokens for it.
CREATE TABLE surge.oauth_resource (
    resource_uri       TEXT PRIMARY KEY,
    service_id         UUID        NOT NULL REFERENCES surge.service(id) ON DELETE CASCADE,
    scopes             TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    -- {scope: "human sentence"} — rendered on the consent screen. A scope
    -- with no entry falls back to its bare name.
    scope_descriptions JSONB       NOT NULL DEFAULT '{}'::JSONB,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_oauth_resource_service ON surge.oauth_resource (service_id);

-- "Which apps are connected to my account?" — and the row that lets the
-- authorize handler skip a screen the user has already answered.
CREATE TABLE surge.oauth_consent (
    client_id    TEXT        NOT NULL REFERENCES surge.oauth_client(client_id) ON DELETE CASCADE,
    identity_id  UUID        NOT NULL REFERENCES surge.identity(id) ON DELETE CASCADE,
    resource_uri TEXT        NOT NULL REFERENCES surge.oauth_resource(resource_uri) ON DELETE CASCADE,
    scopes       TEXT[]      NOT NULL,
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ,
    PRIMARY KEY (client_id, identity_id, resource_uri)
);

CREATE INDEX idx_oauth_consent_identity ON surge.oauth_consent (identity_id);

-- The consent round-trip, shaped like `surge.login_flow`: a short-lived
-- server-side record the auth UI reads over the credential-entry CORS zone.
-- Nothing about the pending grant travels through the browser except this id.
CREATE TABLE surge.oauth_consent_flow (
    id            TEXT PRIMARY KEY,
    client_id     TEXT        NOT NULL REFERENCES surge.oauth_client(client_id) ON DELETE CASCADE,
    identity_id   UUID        NOT NULL REFERENCES surge.identity(id) ON DELETE CASCADE,
    session_id    UUID        NOT NULL,
    resource_uri  TEXT        NOT NULL,
    scopes        TEXT[]      NOT NULL,
    redirect_uri  TEXT        NOT NULL,
    state         TEXT,
    nonce         TEXT,
    code_challenge TEXT       NOT NULL,
    code_challenge_method TEXT NOT NULL,
    csrf_token    TEXT        NOT NULL,
    decided_at    TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Single use is enforced by `consumed_at` under SELECT … FOR UPDATE, not by
-- application-level bookkeeping: code interception is only survivable if the
-- database is the arbiter of "already redeemed".
CREATE TABLE surge.oauth_authorization_code (
    code_hash             BYTEA PRIMARY KEY,
    client_id             TEXT        NOT NULL REFERENCES surge.oauth_client(client_id) ON DELETE CASCADE,
    identity_id           UUID        NOT NULL REFERENCES surge.identity(id) ON DELETE CASCADE,
    session_id            UUID        NOT NULL,
    resource_uri          TEXT        NOT NULL,
    -- Echoed back at the token endpoint and required to match.
    redirect_uri          TEXT        NOT NULL,
    scopes                TEXT[]      NOT NULL,
    code_challenge        TEXT        NOT NULL,
    code_challenge_method TEXT        NOT NULL,
    nonce                 TEXT,
    issued_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ NOT NULL,
    consumed_at           TIMESTAMPTZ
);

CREATE INDEX idx_oauth_code_expires ON surge.oauth_authorization_code (expires_at);

-- Rotated on every use. `family_id` is the lineage: presenting a token that
-- was already consumed revokes the entire family, which is the standard
-- response to a stolen refresh token.
CREATE TABLE surge.oauth_refresh_token (
    token_hash   BYTEA PRIMARY KEY,
    client_id    TEXT        NOT NULL REFERENCES surge.oauth_client(client_id) ON DELETE CASCADE,
    identity_id  UUID        NOT NULL REFERENCES surge.identity(id) ON DELETE CASCADE,
    -- Audit only: the grant is bound to the identity, not to the browser
    -- session that happened to authorize it (internal/oauth-as.md §7).
    session_id   UUID        NOT NULL,
    resource_uri TEXT        NOT NULL,
    scopes       TEXT[]      NOT NULL,
    family_id    UUID        NOT NULL,
    parent_hash  BYTEA,
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX idx_oauth_refresh_family ON surge.oauth_refresh_token (family_id);
CREATE INDEX idx_oauth_refresh_identity ON surge.oauth_refresh_token (identity_id);
CREATE INDEX idx_oauth_refresh_client_identity ON surge.oauth_refresh_token (client_id, identity_id);

-- Private keys sit encrypted under an HKDF-derived key from the versioned
-- pepper, in the same `v{ver}$hex(nonce||ct)` envelope the TOTP path uses —
-- so a database leak alone does not forge tokens, and key rotation follows
-- pepper rotation. A pepper leak, however, is now also a token-forgery event.
CREATE TABLE surge.oauth_signing_key (
    kid                   TEXT PRIMARY KEY,
    algorithm             TEXT        NOT NULL,
    private_key_encrypted TEXT        NOT NULL,
    public_jwk            JSONB       NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at          TIMESTAMPTZ,
    retired_at            TIMESTAMPTZ
);

-- At most one active key. Retired keys stay published in JWKS until every
-- token they signed has expired.
CREATE UNIQUE INDEX idx_oauth_signing_key_active
    ON surge.oauth_signing_key ((TRUE))
    WHERE activated_at IS NOT NULL AND retired_at IS NULL;
