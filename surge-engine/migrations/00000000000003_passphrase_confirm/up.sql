-- Two-phase passphrase enrollment: generate stores unconfirmed, confirm
-- activates it. Mirrors credential_totp's confirmed_at semantics. Existing
-- rows are already active, so backfill them as confirmed.
ALTER TABLE surge.credential_passphrase
    ADD COLUMN confirmed_at TIMESTAMPTZ;

UPDATE surge.credential_passphrase SET confirmed_at = updated_at;
