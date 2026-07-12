CREATE SCHEMA IF NOT EXISTS surge;

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE surge.identity (
    id UUID PRIMARY KEY,
    username CITEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    avatar_url TEXT,
    state TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE surge.credential_password (
    identity_id UUID PRIMARY KEY REFERENCES surge.identity(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE surge.session (
    id UUID PRIMARY KEY,
    token_hash BYTEA UNIQUE NOT NULL,
    identity_id UUID NOT NULL REFERENCES surge.identity(id) ON DELETE CASCADE,
    authenticated_via JSONB NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_session_identity ON surge.session(identity_id);
CREATE INDEX idx_session_expires ON surge.session(expires_at) WHERE revoked_at IS NULL;

CREATE TABLE surge.login_flow (
    id TEXT PRIMARY KEY,
    return_to TEXT,
    csrf_token TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'created',
    attempts INT NOT NULL DEFAULT 0,
    error TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE surge.invite_code (
    code_hash BYTEA PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    used_by UUID REFERENCES surge.identity(id),
    used_at TIMESTAMPTZ
);

CREATE TABLE surge.service (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash BYTEA UNIQUE NOT NULL,
    grants TEXT[] NOT NULL DEFAULT '{}',
    return_origins TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE surge.audit_log (
    id BIGSERIAL PRIMARY KEY,
    at TIMESTAMPTZ NOT NULL,
    actor JSONB NOT NULL,
    action TEXT NOT NULL,
    subject JSONB NOT NULL,
    detail JSONB
);

CREATE INDEX idx_audit_log_at ON surge.audit_log(at);
CREATE INDEX idx_audit_log_action ON surge.audit_log(action);

-- Neutral windowed-counter store. Knows nothing about IPs, actions, or
-- thresholds; callers compose the key and own the policy.
CREATE TABLE surge.rate_limit_window (
    key TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    count INT NOT NULL DEFAULT 0,
    PRIMARY KEY (key, window_start)
);
