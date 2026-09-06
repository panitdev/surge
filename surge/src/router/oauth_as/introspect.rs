//! `POST /oauth2/introspect` (RFC 7662).
//!
//! Authenticated by **service token**, not by client credentials. The caller
//! here is a resource server asking about a token presented to it, and Surge
//! already has a mechanism for authenticating those — the `introspect` grant
//! on `surge.service`. Reusing it means a resource server needs no second
//! credential, and it lets the answer be scoped: a service may only ask about
//! tokens for audiences it owns.
//!
//! This endpoint is what makes revocation authoritative. A resource server
//! that verifies offline accepts the access-token TTL as its revocation
//! window; one that cannot accept that calls here and gets the current truth.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;
use serde_json::json;
use surge_engine::{IdentityId, ServiceToken};

use super::error::{OauthError, OauthErrorCode};
use super::jwt;
use super::AsState;

#[derive(Debug, Deserialize)]
pub(crate) struct IntrospectForm {
    token: Option<String>,
    #[allow(dead_code)]
    token_type_hint: Option<String>,
}

pub(crate) async fn introspect(
    State(state): State<Arc<AsState>>,
    headers: HeaderMap,
    Form(form): Form<IntrospectForm>,
) -> Response {
    match run(&state, &headers, form).await {
        Ok(response) => response,
        Err(e) => e.into_response(),
    }
}

async fn run(
    state: &AsState,
    headers: &HeaderMap,
    form: IntrospectForm,
) -> Result<Response, OauthError> {
    let raw = jwt::bearer_token(headers).ok_or_else(|| {
        OauthError::bearer(
            OauthErrorCode::InvalidClient,
            "introspection requires a Surge service token with the `introspect` grant",
        )
    })?;
    let service_token = ServiceToken::from_raw(raw).ok_or_else(|| {
        OauthError::bearer(OauthErrorCode::InvalidClient, "invalid service token")
    })?;

    let service = state
        .engine
        .verify_service_token(&service_token.hash())
        .await
        .map_err(|_| {
            OauthError::bearer(OauthErrorCode::InvalidClient, "invalid service token")
        })?;

    if !service.grants.iter().any(|g| g == "introspect") {
        return Err(OauthError::new(
            OauthErrorCode::UnauthorizedClient,
            "this service token lacks the `introspect` grant",
        ));
    }

    let Some(token) = form.token else {
        return Err(OauthError::new(
            OauthErrorCode::InvalidRequest,
            "token is required",
        ));
    };

    // RFC 7662 §2.2: every "no" is the same `active: false`. Introspection
    // must not become an oracle that distinguishes expired from forged from
    // revoked from someone-else's-audience.
    let inactive = || Ok(Json(json!({ "active": false })).into_response());

    let keys = state
        .engine
        .public_oauth_signing_keys()
        .await
        .map_err(OauthError::from)?;

    let Ok(claims) = jwt::verify_access_token(&token, state.issuer(), &keys) else {
        return inactive();
    };

    // A service may only introspect tokens for its own audiences. Without
    // this, any service token would read every token this AS ever issued.
    let owned = state
        .engine
        .oauth_resources_for_service(service.id)
        .await
        .map_err(OauthError::from)?;
    if !owned.iter().any(|r| r.resource_uri == claims.aud) {
        return inactive();
    }

    let Ok(identity_id) = claims.sub.parse::<uuid::Uuid>() else {
        return inactive();
    };
    let identity_id = IdentityId::from_uuid(identity_id);

    let live = state
        .engine
        .oauth_grant_is_live(&claims.client_id, identity_id, &claims.aud)
        .await
        .map_err(OauthError::from)?;
    if !live {
        return inactive();
    }

    Ok(Json(json!({
        "active": true,
        "scope": claims.scope,
        "client_id": claims.client_id,
        "sub": claims.sub,
        "aud": claims.aud,
        "iss": claims.iss,
        "exp": claims.exp,
        "iat": claims.iat,
        "jti": claims.jti,
        "sid": claims.sid,
        "token_type": "Bearer",
    }))
    .into_response())
}
