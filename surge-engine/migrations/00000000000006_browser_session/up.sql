-- The composite reference below also verifies the membership's identity.
ALTER TABLE surge.session ADD CONSTRAINT session_id_identity_unique UNIQUE (id, identity_id);

CREATE TABLE surge.browser_session (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash BYTEA UNIQUE NOT NULL CHECK (octet_length(token_hash) = 32),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '720 hours'),
    revoked_at TIMESTAMPTZ,
    default_account_id UUID,
    CHECK (isfinite(issued_at) AND expires_at > issued_at
           AND expires_at <= issued_at + interval '720 hours')
);

CREATE INDEX idx_browser_session_expires ON surge.browser_session(expires_at);

CREATE TABLE surge.browser_session_account (
    browser_session_id UUID NOT NULL REFERENCES surge.browser_session(id) ON DELETE CASCADE,
    account_id UUID NOT NULL DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL,
    session_id UUID UNIQUE NOT NULL,
    PRIMARY KEY (browser_session_id, account_id),
    UNIQUE (browser_session_id, identity_id),
    FOREIGN KEY (session_id, identity_id) REFERENCES surge.session(id, identity_id) ON DELETE CASCADE
);

ALTER TABLE surge.browser_session ADD CONSTRAINT browser_session_default_fk
    FOREIGN KEY (id, default_account_id)
    REFERENCES surge.browser_session_account(browser_session_id, account_id);

-- PostgreSQL 14 cannot clear only one column of a composite foreign key.
CREATE FUNCTION surge.clear_removed_browser_default() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE surge.browser_session SET default_account_id = NULL
    WHERE id = OLD.browser_session_id AND default_account_id = OLD.account_id;
    RETURN OLD;
END;
$$;

CREATE TRIGGER clear_removed_browser_default
BEFORE DELETE ON surge.browser_session_account
FOR EACH ROW EXECUTE FUNCTION surge.clear_removed_browser_default();
