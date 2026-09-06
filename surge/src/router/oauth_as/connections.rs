//! `/v1/account/connections` — the other half of consent.
//!
//! "Show me every app connected to my account, and let me disconnect one" is
//! the reason third-party OAuth is tolerable for the person whose account it
//! is. Issuance without this is not a smaller feature, it is a different and
//! worse one.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde_json::json;
use surge_engine::AuthError;

use super::authorize::current_session;
use super::AsState;
use crate::router::error::ApiError;

pub(crate) async fn list_connections(
    State(state): State<Arc<AsState>>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let session = current_session(&state, &jar)
        .await
        .ok_or(AuthError::InvalidToken)?;

    let connections = state.engine.list_connections(session.identity.id).await?;

    Ok(Json(json!({
        "connections": connections
            .into_iter()
            .map(|c| json!({
                "client_id": c.client_id,
                "client_name": c.client_name,
                "client_uri": c.client_uri,
                "logo_uri": c.logo_uri,
                "dynamically_registered":
                    c.registration_source == surge_engine::oauth::RegistrationSource::Dynamic,
                "resource_uri": c.resource_uri,
                "scopes": c.scopes,
                "granted_at": c.granted_at,
            }))
            .collect::<Vec<_>>(),
    }))
    .into_response())
}

/// Disconnect: revokes the consent *and* every refresh token issued under it,
/// in one transaction. Anything less would leave the app working after the
/// user was told it had been disconnected.
pub(crate) async fn revoke_connection(
    State(state): State<Arc<AsState>>,
    Path(client_id): Path<String>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let session = current_session(&state, &jar)
        .await
        .ok_or(AuthError::InvalidToken)?;

    state
        .engine
        .revoke_connection(session.identity.id, &client_id)
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}
