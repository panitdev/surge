DELETE FROM surge.login_flow WHERE bound_legacy_id IS NOT NULL;
ALTER TABLE surge.login_flow DROP CONSTRAINT login_flow_browser_intent, DROP COLUMN bound_legacy_id, ADD CONSTRAINT login_flow_browser_intent CHECK (
        (login_intent = 'legacy' AND bound_browser_id IS NULL)
        OR login_intent = 'sign_in'
        OR (login_intent = 'add_account' AND bound_browser_id IS NOT NULL)
    );
