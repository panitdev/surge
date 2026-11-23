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
-- The default stays `true` so a writer that predates the column is also safe.
ALTER TABLE surge.oauth_client
    ADD COLUMN scope_ceiling_explicit BOOLEAN NOT NULL DEFAULT true;
