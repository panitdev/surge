-- Whether a client's registration asked for an explicit scope ceiling.
--
--   true  : `scopes` is a ceiling the client asked for (or whose provenance
--           is unknown). Effective scopes at a resource are
--           scopes ∩ the resource's current scopes, so adding a scope to a
--           resource never widens such a client.
--   false : the client registered without naming scopes (dynamic client
--           registration). `scopes` is only a snapshot of the defaults at
--           registration; the effective ceiling is whatever the target
--           resource currently permits.
--
-- Existing rows are backfilled `true`: a stored scope list of unknown
-- provenance is treated as an explicit ceiling, the conservative reading.
-- The default exists only to backfill and is dropped straight away, so every
-- later insert has to state what it means rather than silently becoming an
-- explicit (possibly empty) ceiling.
ALTER TABLE surge.oauth_client
    ADD COLUMN scope_ceiling_explicit BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE surge.oauth_client
    ALTER COLUMN scope_ceiling_explicit DROP DEFAULT;
-- Only a client that registered itself can have omitted its scopes. Admin and
-- platform clients are always explicit.
ALTER TABLE surge.oauth_client
    ADD CONSTRAINT oauth_client_ceiling_provenance
        CHECK (scope_ceiling_explicit OR registration_source IN ('dynamic', 'cimd'));
