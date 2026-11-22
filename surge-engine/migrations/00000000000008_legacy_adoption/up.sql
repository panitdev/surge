ALTER TABLE surge.login_flow
    DROP CONSTRAINT login_flow_browser_intent,
    ADD COLUMN bound_legacy_id UUID REFERENCES surge.session(id) ON DELETE CASCADE,
    ADD CONSTRAINT login_flow_browser_intent CHECK (
        (login_intent = 'legacy' AND bound_browser_id IS NULL AND bound_legacy_id IS NULL)
        OR (login_intent = 'sign_in' AND bound_legacy_id IS NULL)
        OR (login_intent = 'add_account' AND num_nonnulls(bound_browser_id, bound_legacy_id) = 1)
    );
