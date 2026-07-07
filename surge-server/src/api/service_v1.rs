//! Service-facing v1. Retire this module (and its `/v1` mount in
//! `api/mod.rs`) when every `RemoteProvider` caller has been confirmed on
//! v2 — a service-token traffic counter on these routes, or a manifest of
//! which service runs which crate version, showing zero v1 traffic for a
//! sustained window. Not before: `service_v2` currently reuses these
//! handlers, so check that a divergence hasn't been added there first.
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::json;
use surge_engine::types::*;

use super::error::ApiError;
use super::middleware::{require_grant, service_auth, ServiceAuth};
use super::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/sessions/verify", post(verify_session))
        .route("/sessions/revoke", post(revoke_session))
        .route(
            "/identities/{id}/revoke-sessions",
            post(revoke_all_sessions),
        )
        .route("/identities/{id}", get(get_identity))
        .route("/identities", get(get_identity_by_username))
        .route("/identities/{id}/profile", patch(update_profile))
        .route("/register", post(register))
        .route(
            "/register-and-authenticate",
            post(register_and_authenticate),
        )
        .route("/authenticate/password", post(authenticate_password))
        .layer(middleware::from_fn_with_state(state.clone(), service_auth))
        .with_state(state)
}

#[derive(Deserialize)]
pub(crate) struct TokenBody {
    token: String,
}

pub(crate) async fn verify_session(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Json(body): Json<TokenBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "introspect").map_err(|_| AuthError::Forbidden)?;

    let token =
        SessionToken::from_raw(&body.token).ok_or(AuthError::InvalidToken)?;
    let session = state.provider.verify_session(&token).await?;

    state
        .engine
        .audit(
            surge_engine::audit::AuditActor::Service {
                id: auth.service_id.to_string(),
                name: auth.service_name,
            },
            "verify_session",
            json!({"session_id": session.id.to_string()}),
            None,
        )
        .await?;

    Ok(Json(serde_json::to_value(&session).unwrap()))
}

pub(crate) async fn revoke_session(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Json(body): Json<TokenBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "revoke").map_err(|_| AuthError::Forbidden)?;

    let token =
        SessionToken::from_raw(&body.token).ok_or(AuthError::InvalidToken)?;
    state.provider.revoke_session(&token).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub(crate) async fn revoke_all_sessions(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "revoke").map_err(|_| AuthError::Forbidden)?;

    let identity_id = IdentityId::from_uuid(id);
    let revoked = state.provider.revoke_all_sessions(identity_id).await?;
    Ok(Json(json!({"revoked": revoked})))
}

pub(crate) async fn get_identity(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "identity_read").map_err(|_| AuthError::Forbidden)?;

    let identity = state.provider.identity(IdentityId::from_uuid(id)).await?;
    Ok(Json(serde_json::to_value(&identity).unwrap()))
}

#[derive(Deserialize)]
pub(crate) struct UsernameQuery {
    username: String,
}

pub(crate) async fn get_identity_by_username(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Query(query): Query<UsernameQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "identity_read").map_err(|_| AuthError::Forbidden)?;

    let username = Username::new(&query.username)
        .map_err(|e| AuthError::Validation(ValidationError::from(e)))?;
    let identity = state.provider.identity_by_username(&username).await?;

    state
        .engine
        .audit(
            surge_engine::audit::AuditActor::Service {
                id: auth.service_id.to_string(),
                name: auth.service_name,
            },
            "identity_lookup",
            json!({"username": username.as_str()}),
            None,
        )
        .await?;

    Ok(Json(serde_json::to_value(&identity).unwrap()))
}

pub(crate) async fn update_profile(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Path(id): Path<uuid::Uuid>,
    Json(patch): Json<ProfilePatch>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "identity_write").map_err(|_| AuthError::Forbidden)?;

    let identity = state
        .provider
        .update_profile(IdentityId::from_uuid(id), patch)
        .await?;
    Ok(Json(serde_json::to_value(&identity).unwrap()))
}

#[derive(Deserialize)]
pub(crate) struct RegisterBody {
    username: String,
    password: String,
    display_name: String,
}

pub(crate) async fn register(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Json(body): Json<RegisterBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "direct_auth").map_err(|_| AuthError::Forbidden)?;

    let req = parse_register_body(body)?;
    let identity = state.provider.register(req).await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::to_value(&identity).unwrap()),
    ))
}

pub(crate) async fn register_and_authenticate(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Json(body): Json<RegisterBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "direct_auth").map_err(|_| AuthError::Forbidden)?;

    let req = parse_register_body(body)?;
    let issued = state.provider.register_and_authenticate(req).await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(json!({
            "session": serde_json::to_value(&issued.session).unwrap(),
            "token": issued.token.expose_secret(),
        })),
    ))
}

pub(crate) fn parse_register_body(body: RegisterBody) -> Result<RegisterRequest, AuthError> {
    let username = Username::new(&body.username)
        .map_err(|e| AuthError::Validation(ValidationError::from(e)))?;
    let password = Password::new(secrecy::SecretString::from(body.password))
        .map_err(|e| AuthError::Validation(ValidationError::from(e)))?;

    Ok(RegisterRequest {
        username,
        password,
        display_name: body.display_name,
    })
}

#[derive(Deserialize)]
pub(crate) struct AuthenticateBody {
    username: String,
    password: String,
}

pub(crate) async fn authenticate_password(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Json(body): Json<AuthenticateBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "direct_auth").map_err(|_| AuthError::Forbidden)?;

    let username = Username::new(&body.username)
        .map_err(|e| AuthError::Validation(ValidationError::from(e)))?;
    let password = Password::new(secrecy::SecretString::from(body.password))
        .map_err(|e| AuthError::Validation(ValidationError::from(e)))?;

    let issued = state
        .provider
        .authenticate_password(&username, &password)
        .await?;

    Ok(Json(json!({
        "session": serde_json::to_value(&issued.session).unwrap(),
        "token": issued.token.expose_secret(),
    })))
}
