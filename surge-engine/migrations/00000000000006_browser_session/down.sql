ALTER TABLE surge.browser_session DROP CONSTRAINT browser_session_default_fk;
DROP TABLE surge.browser_session_account;
DROP TABLE surge.browser_session;
ALTER TABLE surge.session DROP CONSTRAINT session_id_identity_unique;
