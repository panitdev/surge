//! The OAuth 2.1 / OIDC authorization-server substrate (internal/oauth-as.md).
//!
//! Everything here is storage and state transitions — clients, audiences,
//! consent, codes, refresh lineages, signing keys. Nothing in this module
//! speaks HTTP or knows what a JWT looks like; the wire protocol lives in
//! `surge::router::oauth_as`, and the only cryptographic material that
//! crosses the boundary is [`SigningKeyMaterial`].
//!
//! The reason the AS reads from the same tables as sessions and services:
//! consent ("let this client read your Dispatch resources"), revocation
//! ("show me every app connected to my account") and audience validation
//! ("is this `resource` a service I know?") each need the client half and the
//! identity/service half in a single query.

mod chooser;
mod cimd;
mod client;
mod code;
mod consent;
mod eligibility;
mod key;
mod lifecycle;
mod resource;
mod token;

pub use chooser::ChooserCredential;
pub use cimd::{
    parse_cimd_document, validate_cimd_client_id, CimdMetadata, MAX_CIMD_DOCUMENT_BYTES,
};
pub use client::{validate_redirect_uri, MAX_REGISTRAR_RESOURCES};
pub use code::{AuthorizationSession, verify_pkce, AUTHORIZATION_CODE_TTL_SECS};
pub use consent::ConsentFlowRequest;
pub use eligibility::{
    EligibilityPolicy, cimd_client_may_use_resource, client_may_use_resource, offers_scopes_to_dcr,
    permitted_scopes, registrar_may_bind_resource,
};
pub use key::ES256;
pub use lifecycle::{
    reuse_window, DeleteOutcome, ResourceManager, ResourcePatch, ACCESS_TOKEN_CLOCK_SKEW,
};
pub use resource::canonicalize_resource_uri;
pub use token::RotatedRefresh;
pub(crate) use token::revoke_identity_tokens;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::types::IdentityId;

/// Where a client came from. `Dynamic` is immutable and can never be
/// first-party: an unauthenticated registration endpoint that could mint a
/// consent-skipping client would be a silent token dispenser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationSource {
    Admin,
    Dynamic,
    /// Registered by a registrar service holding `oauth_client_register`.
    /// Third-party and untrusted, and never swept: an administrator revokes it
    /// (registrar revoke is future work).
    Registrar,
    /// Published by the client itself as a client-ID metadata document at its
    /// client ID URL (surge-bcc). Its name, logo and redirect URIs are
    /// self-declared, so it is untrusted and never first-party; the row is a
    /// cache of the last document validated for a consent flow, and is
    /// admitted by the resource's CIMD policy.
    Cimd,
    /// A stored value this build does not recognise (the database constrains
    /// it, so this is a newer or corrupted row). Fails closed: untrusted
    /// metadata, never first-party, and eligible for no resource. Never
    /// accepted from, or created by, a request.
    #[serde(skip_deserializing)]
    Unknown,
}

impl RegistrationSource {
    /// Whether the client's name and logo are supplied by someone other
    /// than the operator, so consent must not present them as verified.
    pub fn metadata_is_untrusted(self) -> bool {
        !matches!(self, Self::Admin)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Dynamic => "dynamic",
            Self::Registrar => "registrar",
            Self::Cimd => "cimd",
            Self::Unknown => "unknown",
        }
    }

    fn from_db(s: &str) -> Self {
        match s {
            "dynamic" => Self::Dynamic,
            "registrar" => Self::Registrar,
            "cimd" => Self::Cimd,
            "admin" => Self::Admin,
            // Must not fail open: `Unknown` is untrusted and has no access.
            _ => Self::Unknown,
        }
    }
}

/// A registered OAuth client. Never carries the client secret: like every
/// other credential in Surge, that leaves the engine exactly once, at
/// creation, in the return value of [`crate::Engine::create_oauth_client`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OauthClient {
    pub client_id: String,
    pub client_name: String,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub registration_source: RegistrationSource,
    pub first_party: bool,
    pub trust_state: String,
    /// Whether the client authenticates with a secret. A public client
    /// (`false`) is the normal MCP case and is only safe because PKCE is
    /// mandatory.
    pub confidential: bool,
    /// Canonical URIs of the registrations this client is approved for.
    /// `None` is the legacy default: no explicit list. `Some(vec![])` is an
    /// explicit list that approves nothing.
    pub audiences: Option<Vec<String>>,
    /// The service that registered a [`RegistrationSource::Registrar`]
    /// client. `None` for every other source.
    pub registrar_service_id: Option<Uuid>,
    /// True when `scopes` is a ceiling the registration asked for, or one of
    /// unknown provenance (every row that predates the column). Effective
    /// scopes at a resource are then `scopes ∩ resource.scopes`. False for a
    /// dynamic client that registered without naming scopes: `scopes` is a
    /// snapshot, and the ceiling is whatever the target currently permits.
    /// See [`permitted_scopes`].
    pub scope_ceiling_explicit: bool,
    pub created_at: DateTime<Utc>,
}

/// What a caller must supply to register a client. `registration_source`
/// decides which rules apply: `Dynamic` can never set `first_party` and is
/// held to the redirect-URI scheme rules in `internal/oauth-as.md` §5.3.
#[derive(Debug, Clone)]
pub struct NewOauthClient {
    pub client_name: String,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub confidential: bool,
    pub first_party: bool,
    pub registration_source: RegistrationSource,
    /// Canonical URIs to approve this client for, each resolved to the
    /// registration that holds it at creation time. `None` stores no
    /// explicit list.
    pub audiences: Option<Vec<String>>,
}

/// How a protected resource came to be registered. Immutable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceSource {
    /// Surge’s built-in audience for UserInfo access tokens.
    #[serde(skip_deserializing)]
    UserInfo,
    /// A first-party resource server owned by a registered service, which is
    /// the one service allowed to introspect its tokens.
    Service,
    /// Registered on a developer's behalf by a delegated registrar. Owned by
    /// no service.
    Delegated,
    /// A stored value this build does not recognise. Fails closed: no client
    /// is eligible, no registrar manages it, no service introspects for it.
    /// Never accepted from a request.
    #[serde(skip_deserializing)]
    Unknown,
}

impl ResourceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserInfo => "userinfo",
            Self::Service => "service",
            Self::Delegated => "delegated",
            Self::Unknown => "unknown",
        }
    }

    pub(crate) fn from_db(s: &str) -> Self {
        match s {
            "userinfo" => Self::UserInfo,
            "service" => Self::Service,
            "delegated" => Self::Delegated,
            _ => Self::Unknown,
        }
    }
}

/// Reserved audience for Surge’s UserInfo endpoint. Resource registration
/// accepts only HTTP(S) URLs, so external resource servers cannot claim it.
pub const USERINFO_AUDIENCE: &str = "urn:surge:oauth:userinfo";

/// An audience registration: one resource server at one canonical URI.
///
/// `registration_id` is the identity every grant is bound to. It never
/// changes, and re-registering a URI after deletion yields a new one, so
/// nothing granted against the old registration carries over. The URI is
/// what clients request and what the JWT `aud` claim carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OauthResource {
    pub registration_id: Uuid,
    pub resource_uri: String,
    pub registration_source: ResourceSource,
    /// The owning service of a [`ResourceSource::Service`] registration —
    /// the service allowed to introspect its tokens. Always `None` for a
    /// delegated registration.
    pub service_id: Option<Uuid>,
    /// The authenticated service that created the registration. `None` when
    /// unknown: registrations that predate registrar tracking, and those an
    /// operator created through the CLI.
    pub registrar_service_id: Option<Uuid>,
    pub scopes: Vec<String>,
    /// `{scope: "human sentence"}`, rendered on the consent screen. A scope
    /// with no entry falls back to its bare name.
    pub scope_descriptions: serde_json::Value,
    /// Exact CIMD client-ID URLs allowed to use this resource.
    pub allowed_cimd_client_ids: Vec<String>,
    /// Admit valid public CIMD clients independently of the exact allowlist.
    #[serde(default)]
    pub cimd_open: bool,
    /// Whether dynamically registered clients may use this resource without
    /// an explicit audience binding.
    pub dcr_enabled: bool,
    /// Registrar services whose clients may be bound to this registration,
    /// beyond the delegated registrations a registrar created itself. Set by
    /// the owner; empty admits none.
    #[serde(default)]
    pub allowed_client_registrars: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// A live consent record: this identity has approved these scopes for this
/// client at this resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ConsentGrant {
    pub client_id: String,
    pub identity_id: IdentityId,
    pub registration_id: Uuid,
    pub resource_uri: String,
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
}

/// One row of "which apps are connected to my account?".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Connection {
    pub client_id: String,
    pub client_name: String,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub registration_source: RegistrationSource,
    pub resource_uri: String,
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
}

/// The pending authorization a consent screen is deciding on. Shaped like
/// `login_flow`: the browser carries only the flow id, never the grant.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConsentFlow {
    pub id: String,
    pub client_id: String,
    pub identity_id: IdentityId,
    pub session_id: Uuid,
    pub account_id: Option<Uuid>,
    pub registration_id: Uuid,
    pub resource_uri: String,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
}

/// Everything an authorization code stands for, supplied at mint time and
/// handed back — once — at redemption.
#[derive(Debug, Clone)]
pub struct AuthorizationGrant {
    pub client_id: String,
    pub identity_id: IdentityId,
    pub session_id: Uuid,
    /// The registration the grant was decided against. Minting fails if it
    /// no longer holds `resource_uri`.
    pub registration_id: Uuid,
    pub resource_uri: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
}

/// A refresh token's grant. Constructed by the AS router when a code is
/// redeemed, and recovered from storage by rotation — so unlike the other
/// types here it is deliberately not `#[non_exhaustive]`.
#[derive(Debug, Clone)]
pub struct RefreshGrant {
    pub client_id: String,
    pub identity_id: IdentityId,
    pub session_id: Uuid,
    pub registration_id: Uuid,
    pub resource_uri: String,
    pub scopes: Vec<String>,
    pub family_id: Uuid,
}

/// Signing material for one key, decrypted. The private half is a PKCS#8 DER
/// blob in a `Zeroizing` buffer — the caller signs with it and drops it; it is
/// never cloned into a long-lived cache, because the encrypted-at-rest
/// property is worth more than the microseconds a cache would save.
pub struct SigningKeyMaterial {
    pub kid: String,
    pub algorithm: String,
    pub pkcs8_der: Zeroizing<Vec<u8>>,
    pub public_jwk: serde_json::Value,
}

impl std::fmt::Debug for SigningKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyMaterial")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .field("pkcs8_der", &"***")
            .finish()
    }
}

/// The public half, as published in JWKS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PublicSigningKey {
    pub kid: String,
    pub algorithm: String,
    pub public_jwk: serde_json::Value,
    pub activated_at: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
}

pub(crate) fn now() -> DateTime<Utc> {
    Utc::now()
}

/// Maps a write that names a registration which no longer holds its URI —
/// deleted, or deleted and registered again — to `NotFound` instead of an
/// internal error. The composite foreign key is what detects it.
pub(crate) fn stale_registration(e: diesel::result::Error) -> crate::AuthError {
    use diesel::result::{DatabaseErrorKind, Error};
    match e {
        Error::DatabaseError(DatabaseErrorKind::ForeignKeyViolation, _) => {
            crate::AuthError::NotFound
        }
        other => crate::AuthError::Internal(other.into()),
    }
}

impl crate::Engine {
    /// The AS's share of the background sweep: expire what has expired,
    /// retire what should be retired, and drop dynamic registrations nobody
    /// ever used.
    ///
    /// `retire_grace` is derived from the access-token TTL rather than
    /// configured separately — a retired key must outlive every token it
    /// signed, and "two access-token lifetimes" is that statement with a
    /// margin, not a tunable preference.
    pub async fn run_oauth_maintenance(
        &self,
        key_rotation: std::time::Duration,
        access_ttl: std::time::Duration,
        dcr_ttl: std::time::Duration,
    ) -> Result<(), crate::AuthError> {
        self.gc_expired_authorization_codes().await?;
        self.gc_expired_resource_reservations().await?;
        self.gc_expired_consent_flows().await?;
        self.gc_expired_chooser_requests().await?;
        self.gc_expired_refresh_tokens().await?;
        self.gc_unused_dynamic_clients(dcr_ttl).await?;
        // The same idle window governs unreferenced CIMD rows.
        self.gc_unused_cimd_clients(dcr_ttl).await?;
        self.rotate_oauth_signing_keys(key_rotation, access_ttl * 2)
            .await?;
        Ok(())
    }
}
