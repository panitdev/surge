//! Login/consent bridge between Hydra (the OAuth 2.1 authorization server,
//! per rfc.md) and Surge's session/flow substrate. Mounted only when the
//! embedder opts in (`BrowserRouterConfig`'s `oauth_bridge` field is
//! `Some`) — absent that, this module's routes simply aren't mounted and
//! Hydra is never required for Surge to run.
//!
//! This module knows about `surge_session` and the flow round-trip; it
//! treats Hydra as an opaque "accept this challenge, hand back a redirect
//! URL" dependency via `crate::hydra::HydraAdmin` — the only Hydra-aware
//! type it references.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::json;

use crate::hydra::{HydraAdmin, HydraError};
use crate::{AuthProvider, SessionToken};

#[derive(Clone)]
pub struct OauthBridgeConfig {
    pub hydra_admin_url: url::Url,
    pub hydra_admin_timeout: Duration,
    /// This server's own public origin (e.g. `https://auth.panit.dev`),
    /// used to build the self-referential `return_to` callback that
    /// re-enters the login-challenge handler once `surge_session` is set.
    /// Must be present in the deployment's registered return origins, or
    /// `GET /v1/login`'s return_to validation will reject it.
    pub bridge_origin: String,
}

struct BridgeState {
    provider: Arc<dyn AuthProvider>,
    hydra: HydraAdmin,
    bridge_origin: String,
}

enum BridgeError {
    Session(crate::AuthError),
    Hydra(HydraError),
}

impl From<crate::AuthError> for BridgeError {
    fn from(e: crate::AuthError) -> Self {
        Self::Session(e)
    }
}

impl From<HydraError> for BridgeError {
    fn from(e: HydraError) -> Self {
        Self::Hydra(e)
    }
}

impl IntoResponse for BridgeError {
    fn into_response(self) -> Response {
        use axum::http::StatusCode;
        match self {
            BridgeError::Session(e) => {
                super::error::ApiError::from(e).into_response()
            }
            BridgeError::Hydra(e) => {
                (StatusCode::BAD_GATEWAY, Json(json!({ "error": "upstream_oauth_error", "message": e.to_string() })))
                    .into_response()
            }
        }
    }
}

pub fn router(provider: Arc<dyn AuthProvider>, config: OauthBridgeConfig) -> Router {
    let hydra = HydraAdmin::new(config.hydra_admin_url, config.hydra_admin_timeout)
        .expect("hydra admin client config is static and always valid");

    let state = Arc::new(BridgeState {
        provider,
        hydra,
        bridge_origin: config.bridge_origin,
    });

    Router::new()
        .route("/oauth/login", get(login_challenge))
        .route("/oauth/consent", get(consent_challenge))
        .with_state(state)
}

#[derive(Deserialize)]
struct LoginChallengeQuery {
    login_challenge: String,
}

async fn login_challenge(
    State(state): State<Arc<BridgeState>>,
    Query(query): Query<LoginChallengeQuery>,
    jar: CookieJar,
) -> Result<Response, BridgeError> {
    let valid_session = match jar.get("surge_session") {
        Some(cookie) => match SessionToken::from_raw(cookie.value()) {
            Some(token) => state.provider.verify_session(&token).await.ok(),
            None => None,
        },
        None => None,
    };

    if let Some(session) = valid_session {
        let redirect_to = state
            .hydra
            .accept_login(&query.login_challenge, &session.identity.id.to_string())
            .await?;
        return Ok(Redirect::to(&redirect_to).into_response());
    }

    // No valid session (missing, expired, or otherwise invalid) — re-check
    // on every challenge rather than trusting any Hydra-side "remember me"
    // signal. Bounce into the existing flow-init, with return_to pointing
    // right back at this handler so the round-trip re-enters it once
    // surge_session is set.
    let self_url = format!(
        "{}/v1/oauth/login?login_challenge={}",
        state.bridge_origin,
        percent_encode(&query.login_challenge)
    );
    let redirect_url = format!(
        "{}/v1/login?return_to={}",
        state.bridge_origin,
        percent_encode(&self_url)
    );
    Ok(Redirect::to(&redirect_url).into_response())
}

fn percent_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[derive(Deserialize)]
struct ConsentChallengeQuery {
    consent_challenge: String,
}

async fn consent_challenge(
    State(state): State<Arc<BridgeState>>,
    Query(query): Query<ConsentChallengeQuery>,
) -> Result<Response, BridgeError> {
    let redirect_to = state.hydra.skip_consent(&query.consent_challenge).await?;
    Ok(Redirect::to(&redirect_to).into_response())
}
