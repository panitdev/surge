//! `GET|POST /oauth2/userinfo` — the OIDC claims endpoint.
//!
//! Reads only what the identity already publishes to any service holding
//! `identity_read`. Nothing here is derived from the OAuth grant beyond
//! "which identity": a token minted for userinfo's own audience with the
//! `openid` scope gets in, and the claims are the same for every such token.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use surge_engine::IdentityId;

use super::AsState;
use super::error::{OauthError, OauthErrorCode};
use super::jwt;

pub(crate) async fn userinfo(State(state): State<Arc<AsState>>, headers: HeaderMap) -> Response {
    match run(&state, &headers).await {
        Ok(response) => response,
        Err(e) => e.into_response(),
    }
}

async fn run(state: &AsState, headers: &HeaderMap) -> Result<Response, OauthError> {
    if !state.config.enable_oidc {
        return Err(OauthError::new(
            OauthErrorCode::InvalidRequest,
            "OIDC is not enabled on this deployment",
        ));
    }

    let token = jwt::bearer_token(headers).ok_or_else(|| {
        OauthError::bearer(
            OauthErrorCode::InvalidToken,
            "a bearer access token is required",
        )
    })?;

    let keys = state
        .engine
        .public_oauth_signing_keys()
        .await
        .map_err(OauthError::from)?;
    let claims = jwt::verify_access_token(token, state.issuer(), &keys)?;

    // A token minted for a resource is that resource's to accept, even when
    // its grant also asked for `openid` (RFC 9068 §4). Userinfo has its own
    // audience, and only an `openid` sign-in is minted for it.
    if claims.aud != surge_engine::oauth::USERINFO_AUDIENCE {
        return Err(OauthError::bearer(
            OauthErrorCode::InvalidToken,
            "this access token was not issued for userinfo",
        ));
    }
    if !claims.scope.split_whitespace().any(|s| s == "openid") {
        return Err(OauthError::bearer(
            OauthErrorCode::InvalidToken,
            "this token does not carry the openid scope",
        ));
    }

    let identity_id = claims
        .sub
        .parse::<uuid::Uuid>()
        .map(IdentityId::from_uuid)
        .map_err(|_| OauthError::bearer(OauthErrorCode::InvalidToken, "malformed subject"))?;

    let identity = state
        .provider
        .identity(identity_id)
        .await
        .map_err(OauthError::from)?;

    Ok(Json(json!({
        "sub": claims.sub,
        "preferred_username": identity.username.as_str(),
        "name": identity.display_name,
        "picture": identity.avatar_url.as_ref().map(|u| u.to_string()),
    }))
    .into_response())
}
