-- Reserved canonical URIs.
--
-- Deleting a registration ends every grant bound to it, but access tokens
-- already issued for the URI are self-contained JWTs that resource servers
-- verify offline: they stay acceptable until they expire (plus the clock skew
-- verifiers allow). If the URI could be registered again at once, a token
-- issued for the old registration would validate at whoever registers it
-- next. So a deletion leaves a reservation behind, and a URI with a live one
-- cannot be registered until `reserved_until`.
--
-- Not a foreign key and keyed by URI: it must outlive the registration it
-- describes, and there is at most one live reservation per URI (a URI is
-- reserved only after its registration is deleted and cannot be registered
-- again until the reservation ends; an expired leftover is replaced by the
-- next deletion).
CREATE TABLE surge.oauth_resource_reservation (
    resource_uri        TEXT PRIMARY KEY,
    -- The deleted registration. Lets a retried delete that names this id
    -- recognise that it already happened instead of touching a successor.
    registration_id     UUID NOT NULL UNIQUE,
    registration_source TEXT NOT NULL,
    service_id          UUID,
    registrar_service_id UUID,
    deleted_at          TIMESTAMPTZ NOT NULL,
    reserved_until      TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_oauth_resource_reservation_until
    ON surge.oauth_resource_reservation (reserved_until);
