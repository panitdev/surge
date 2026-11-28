-- Registrar services whose clients a resource admits, beyond the delegated
-- registrations a registrar created itself. Empty admits none.
ALTER TABLE surge.oauth_resource
    ADD COLUMN allowed_client_registrars UUID[] NOT NULL DEFAULT '{}';
