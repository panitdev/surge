//! `POST /oauth2/revoke` (RFC 7009).
//!
//! Revoking one refresh token takes down its whole family: a client saying
//! "I'm done with this grant" means the grant is over, not that one link in a
//! rotation chain is. Access tokens already outstanding are not recalled —
//! they cannot be — which is what the short TTL is for.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;
use surge_engine::{ClientSecret, RefreshToken};

use super::error::{OauthError, OauthErrorCode};
use super::AsState;

#[derive(Debug, Deserialize)]
pub(crate) struct RevokeForm {
    token: Option<String>,
    #[allow(dead_code)]
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

pub(crate) async fn revoke(
    State(state): State<Arc<AsState>>,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
) -> Response {
    match run(&state, &headers, form).await {
        Ok(response) => response,
        Err(e) => e.into_response(),
    }
}

async fn run(
    state: &AsState,
    headers: &HeaderMap,
    form: RevokeForm,
) -> Result<Response, OauthError> {
    let basic = super::token::basic_auth(headers);
    let basic_id = basic.as_ref().map(|(id, _)| id.clone());
    let basic_secret = basic.and_then(|(_, secret)| secret);
    let client_id = basic_id.or(form.client_id).ok_or_else(|| {
        OauthError::new(OauthErrorCode::InvalidClient, "client_id is required")
    })?;

    let client = state
        .engine
        .get_oauth_client(&client_id)
        .await
        .map_err(|_| OauthError::new(OauthErrorCode::InvalidClient, "unknown client"))?;

    if client.confidential {
        let secret = basic_secret
            .or(form.client_secret)
            .and_then(|s| ClientSecret::from_raw(&s))
            .ok_or_else(|| {
                OauthError::new(
                    OauthErrorCode::InvalidClient,
                    "this client is confidential and must authenticate",
                )
            })?;
        state
            .engine
            .verify_client_secret(&client_id, &secret)
            .await
            .map_err(|_| {
                OauthError::new(OauthErrorCode::InvalidClient, "client authentication failed")
            })?;
    }

    // RFC 7009 §2.2: an unknown or unparseable token is a *successful*
    // revocation. Reporting otherwise would turn this into a token oracle.
    if let Some(token) = form.token.as_deref().and_then(RefreshToken::from_raw) {
        state
            .engine
            .revoke_refresh_token(&token, &client_id)
            .await
            .map_err(OauthError::from)?;
    }

    Ok(StatusCode::OK.into_response())
}
