ALTER TABLE surge.login_flow
    ADD COLUMN login_intent TEXT NOT NULL DEFAULT 'legacy',
    ADD COLUMN bound_browser_id UUID REFERENCES surge.browser_session(id) ON DELETE CASCADE,
    ADD CONSTRAINT login_flow_browser_intent CHECK (
        (login_intent = 'legacy' AND bound_browser_id IS NULL)
        OR login_intent = 'sign_in'
        OR (login_intent = 'add_account' AND bound_browser_id IS NOT NULL)
    );
