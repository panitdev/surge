-- TOTP second factor. The secret must be recoverable to verify codes, so it
-- is stored encrypted (XChaCha20-Poly1305, key HKDF-derived from the versioned
-- pepper) as `v{ver}$hex(nonce||ciphertext)` — never a one-way hash.
CREATE TABLE surge.credential_totp (
    identity_id UUID PRIMARY KEY REFERENCES surge.identity(id) ON DELETE CASCADE,
    secret_encrypted TEXT NOT NULL,
    confirmed_at TIMESTAMPTZ,       -- NULL until the user confirms one code
    last_used_step BIGINT,          -- last accepted TOTP step, for replay prevention
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Standalone passphrase factor (server-generated Diceware). One-way hashed
-- with the same peppered-Argon2 machinery as credential_password.
CREATE TABLE surge.credential_passphrase (
    identity_id UUID PRIMARY KEY REFERENCES surge.identity(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Carries the password-verified identity across the mandatory TOTP step of a
-- login flow (state = 'awaiting_totp').
ALTER TABLE surge.login_flow
    ADD COLUMN identity_id UUID REFERENCES surge.identity(id) ON DELETE CASCADE;
