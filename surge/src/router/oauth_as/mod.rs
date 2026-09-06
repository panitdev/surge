//! Surge as a native OAuth 2.1 / OIDC authorization server
//! (internal/oauth-as.md).
//!
//! # Why these paths are not versioned
//!
//! `internal/api-exposure-philosophy.md` §3 says the browser surface nests
//! every live version and has no version-free default. This surface is the
//! documented exception. RFC 8414 and RFC 9728 fix the two `.well-known`
//! paths at the origin root — they cannot live under `/v1` — and every other
//! endpoint here is discovered *from* that metadata document, so a `/vN`
//! prefix would buy nothing: no client hardcodes `/oauth2/token`, it reads
//! `token_endpoint`. The OAuth spec version, not Surge's, is the
//! compatibility contract for this surface.
//!
//! The substrate invariant is untouched. An access token is a new kind of
//! credential; once minted it means one thing forever, exactly like a session.
//!
//! # Only central mounts this
//!
//! An authorization server has exactly one issuer identity, so
//! `RemoteProvider` must never proxy `/oauth2/*` — see the note on
//! `BrowserRouterConfig::oauth_as`. A service proxying `/oauth2/token` would
//! be issuing tokens under central's `iss` from its own origin, and the
//! client-side issuer check would fail in ways that look like clock skew.

mod authorize;
mod connections;
mod consent;
mod discovery;
mod error;
mod introspect;
mod jwt;
mod register;
mod revoke;
mod token;
mod userinfo;

use std::sync::Arc;
use std::time::Duration;

use axum::routing::{delete, get, post};
use axum::Router;
use surge_engine::Engine;
use tower_http::cors::{Any, CorsLayer};

use super::rate_limit::RateLimiter;
use crate::AuthProvider;

/// Everything the AS needs that is not already in the database.
///
/// Presence of this config in `BrowserRouterConfig` is the on-switch: unset
/// means no routes are mounted, no signing key is ever generated, and nothing
/// about the deployment changes.
#[derive(Clone)]
pub struct OauthAsConfig {
    /// This server's public origin. Becomes `iss`, and is the base for every
    /// URL in the discovery document — so it must match what clients actually
    /// dial, character for character.
    pub issuer: String,
    /// Where the consent screen lives. The AS redirects here with a
    /// `consent_flow` id; the UI reads the flow over the credential-entry
    /// CORS zone.
    pub auth_ui_origin: String,
    /// Access-token lifetime. This *is* the revocation window for any
    /// resource server that verifies offline rather than introspecting, so
    /// it is short by default and should be read as a security parameter.
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
    pub key_rotation: Duration,
    /// RFC 7591 dynamic client registration. Off by default: the endpoint is
    /// unauthenticated by specification, which makes it the largest abuse
    /// surface here.
    pub allow_dynamic_registration: bool,
    /// Reject `authorize` without a resolvable `resource` (RFC 8707). The
    /// MCP-correct default; turning it off is only for deployments with a
    /// single audience that predates resource indicators.
    pub require_resource: bool,
    /// The audience to assume when `require_resource` is false and the client
    /// sent none.
    pub default_resource: Option<String>,
    pub dcr_ttl: Duration,
    /// Serve `/.well-known/openid-configuration` alongside the OAuth metadata
    /// and honour the `openid` scope (ID tokens, `userinfo`).
    pub enable_oidc: bool,
}

pub(crate) struct AsState {
    pub engine: Arc<Engine>,
    pub provider: Arc<dyn AuthProvider>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub config: OauthAsConfig,
}

impl AsState {
    pub(crate) fn issuer(&self) -> &str {
        self.config.issuer.trim_end_matches('/')
    }

    pub(crate) fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.issuer())
    }
}

/// The root-mounted half: everything on the OAuth wire.
///
/// CORS here is deliberately *not* the credentialed narrow zone the rest of
/// Surge uses. These endpoints authenticate with a code, a client secret or a
/// bearer token, never with a cookie, so allowing any origin without
/// credentials is both required (browser-based OAuth clients live on origins
/// Surge has never heard of) and safe (no ambient authority to ride on).
pub(crate) fn root_router(state: Arc<AsState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([http::Method::GET, http::Method::POST, http::Method::OPTIONS])
        .allow_headers(Any);

    let mut oauth2 = Router::new()
        .route("/oauth2/authorize", get(authorize::authorize))
        .route("/oauth2/token", post(token::token))
        .route("/oauth2/jwks.json", get(discovery::jwks))
        .route("/oauth2/introspect", post(introspect::introspect))
        .route("/oauth2/revoke", post(revoke::revoke))
        .route("/oauth2/userinfo", get(userinfo::userinfo).post(userinfo::userinfo))
        .route(
            "/.well-known/oauth-authorization-server",
            get(discovery::metadata),
        );

    if state.config.enable_oidc {
        oauth2 = oauth2.route("/.well-known/openid-configuration", get(discovery::metadata));
    }

    if state.config.allow_dynamic_registration {
        oauth2 = oauth2.route("/oauth2/register", post(register::register));
    }

    oauth2.layer(cors).with_state(state)
}

/// The `/v1` half: Surge's own browser API for the consent screen and account
/// settings, consumed by Surge's own auth UI.
///
/// These are under `/v1` and not `/oauth2/*` on purpose. They are not part of
/// the OAuth wire protocol — no third-party client ever calls them — so they
/// version with the browser surface like everything else it contains.
pub(crate) fn v1_router(state: Arc<AsState>, session_cors: CorsLayer) -> Router {
    let credential_entry = Router::new()
        .route(
            "/oauth/consent/{flow_id}",
            get(consent::get_consent_flow).post(consent::decide_consent_flow),
        )
        .layer(super::cors::narrow(&state.config.auth_ui_origin))
        .with_state(Arc::clone(&state));

    // Disconnecting an app is a state-changing, cookie-authenticated call:
    // it carries the same header-CSRF requirement as logout and factor
    // changes, and sits in the same CORS zone as the rest of session
    // management.
    let session_zone = Router::new()
        .route("/account/connections", get(connections::list_connections))
        .route(
            "/account/connections/{client_id}",
            delete(connections::revoke_connection)
                .layer(axum::middleware::from_fn(crate::extract::require_header_csrf)),
        )
        .layer(session_cors)
        .with_state(state);

    Router::new().merge(credential_entry).merge(session_zone)
}

/// The AS's background sweep: signing-key rotation, code and consent-flow
/// expiry, refresh-token cleanup, and the unused dynamic-client sweep.
///
/// Started by mounting the AS, for the same reason the session sweep is
/// started by mounting the browser router: a deployment that mounts an
/// authorization server and never rotates a signing key is a deployment
/// nobody chose.
pub(crate) fn spawn_oauth_maintenance(
    engine: Arc<Engine>,
    config: OauthAsConfig,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = engine
                .run_oauth_maintenance(config.key_rotation, config.access_ttl, config.dcr_ttl)
                .await
            {
                tracing::warn!(error = %e, "surge oauth maintenance sweep failed");
            }
        }
    })
}
