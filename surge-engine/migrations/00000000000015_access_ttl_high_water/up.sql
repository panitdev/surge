-- The longest access-token lifetime this deployment has ever been configured
-- with. A deleted resource's URI is reserved for that long (plus clock skew),
-- because tokens issued under an earlier, longer setting are still valid
-- after the setting is lowered, and because the operator CLI does not read
-- the server's environment. Raised at server startup; never lowered
-- automatically.
CREATE TABLE surge.oauth_access_ttl_high_water (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    max_access_ttl_secs BIGINT NOT NULL CHECK (max_access_ttl_secs > 0)
);
