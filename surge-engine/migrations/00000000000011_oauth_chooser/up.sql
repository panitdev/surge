ALTER TABLE surge.browser_session ADD COLUMN provisional boolean NOT NULL DEFAULT false;
CREATE TABLE surge.oauth_authorization_request (
    id text PRIMARY KEY,
    browser_id uuid REFERENCES surge.browser_session(id) ON DELETE CASCADE,
    legacy_id uuid REFERENCES surge.session(id) ON DELETE CASCADE,
    CHECK (num_nonnulls(browser_id, legacy_id) = 1),
    request jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    login_id text UNIQUE REFERENCES surge.login_flow(id) ON DELETE CASCADE,
    session_id uuid
);
CREATE INDEX oauth_authorization_request_expiry ON surge.oauth_authorization_request(expires_at);
