-- An identity_link is an assertion that some external namespace's subject
-- belongs to a Surge identity: ('email', 'alice@example.com'),
-- ('google', '117...'). The pair is opaque to Surge — it never parses either
-- column — which is what makes the table provider-agnostic.
--
-- verified_at is load-bearing, not decorative: only a verified link may
-- authenticate. An unverified row is a pending claim (an address someone
-- typed into account settings), and carries no authority until whoever
-- established proof of control sets the timestamp.
CREATE TABLE surge.identity_link (
    provider    TEXT        NOT NULL,
    subject     TEXT        NOT NULL,
    identity_id UUID        NOT NULL REFERENCES surge.identity(id) ON DELETE CASCADE,
    verified_at TIMESTAMPTZ,
    linked_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject)
);

-- Listing an identity's links ("which accounts are connected?") is a
-- per-identity query; the primary key only serves the reverse direction.
CREATE INDEX idx_identity_link_identity_id ON surge.identity_link (identity_id);
