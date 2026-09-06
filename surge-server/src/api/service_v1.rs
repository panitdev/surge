//! Service-facing API (v1).
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
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
        .route("/authenticate/link", post(authenticate_by_link))
        .route(
            "/identities/{id}/links",
            get(identity_links).post(link_identity).delete(unlink_identity),
        )
        .route("/oauth/clients", get(list_oauth_clients).post(create_oauth_client))
        .route("/oauth/clients/{client_id}", delete(revoke_oauth_client))
        .route(
            "/oauth/resources",
            get(list_oauth_resources).post(create_oauth_resource),
        )
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
    let session = state.provider.verify_session(Some(token)).await?;

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

/// Both columns are `TEXT`, so this is a policy cap rather than a column
/// width — it bounds what a caller can push through, not what fits.
const MAX_LINK_REF_LEN: usize = 255;

/// `provider` and `subject` together address an external account. Neither is
/// interpreted here — the pair is opaque to Surge — but an empty or unbounded
/// value is never a real account reference, and `subject` is matched verbatim
/// against a primary key.
fn validate_link_ref(provider: &str, subject: &str) -> Result<(), AuthError> {
    for (field, value) in [("provider", provider), ("subject", subject)] {
        if value.is_empty() {
            return Err(AuthError::Validation(ValidationError::Field {
                field,
                message: "must not be empty".into(),
            }));
        }
        if value.len() > MAX_LINK_REF_LEN {
            return Err(AuthError::Validation(ValidationError::Field {
                field,
                message: format!("must be at most {MAX_LINK_REF_LEN} bytes"),
            }));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub(crate) struct LinkSeedBody {
    username: String,
    display_name: String,
}

#[derive(Deserialize)]
pub(crate) struct AuthenticateLinkBody {
    provider: String,
    subject: String,
    seed: LinkSeedBody,
}

/// Sign in through an external provider, creating the identity on first sight.
/// `201` distinguishes the signup from the `200` returning-login so a caller
/// can branch without reading the body.
pub(crate) async fn authenticate_by_link(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Json(body): Json<AuthenticateLinkBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "external_auth").map_err(|_| AuthError::Forbidden)?;

    validate_link_ref(&body.provider, &body.subject)?;

    let username = Username::new(&body.seed.username)
        .map_err(|e| AuthError::Validation(ValidationError::from(e)))?;
    let seed = LinkSeed {
        username,
        display_name: body.seed.display_name,
    };

    let auth = state
        .provider
        .authenticate_by_link(&body.provider, &body.subject, &seed)
        .await?;

    let status = if auth.created {
        axum::http::StatusCode::CREATED
    } else {
        axum::http::StatusCode::OK
    };

    Ok((
        status,
        Json(json!({
            "session": serde_json::to_value(&auth.issued.session).unwrap(),
            "token": auth.issued.token.expose_secret(),
            "created": auth.created,
        })),
    ))
}

#[derive(Deserialize)]
pub(crate) struct LinkBody {
    provider: String,
    subject: String,
    #[serde(default)]
    verified: bool,
}

pub(crate) async fn link_identity(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<LinkBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "external_link").map_err(|_| AuthError::Forbidden)?;

    validate_link_ref(&body.provider, &body.subject)?;

    let link = state
        .provider
        .link_identity(
            IdentityId::from_uuid(id),
            &body.provider,
            &body.subject,
            body.verified,
        )
        .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::to_value(&link).unwrap()),
    ))
}

pub(crate) async fn identity_links(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Path(id): Path<uuid::Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "identity_read").map_err(|_| AuthError::Forbidden)?;

    let links = state
        .provider
        .identity_links(IdentityId::from_uuid(id))
        .await?;

    Ok(Json(serde_json::to_value(&links).unwrap()))
}

#[derive(Deserialize)]
pub(crate) struct UnlinkBody {
    provider: String,
    subject: String,
}

pub(crate) async fn unlink_identity(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<UnlinkBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "external_link").map_err(|_| AuthError::Forbidden)?;

    validate_link_ref(&body.provider, &body.subject)?;

    state
        .provider
        .unlink_identity(IdentityId::from_uuid(id), &body.provider, &body.subject)
        .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// -- OAuth authorization-server administration (internal/oauth-as.md §2) --
//
// Behind its own `oauth_admin` grant rather than folded into
// `identity_write`: registering a client is not an identity operation, and a
// service that manages users has no business minting OAuth clients. The
// `first_party` flag in particular skips the consent screen, so the grant
// that can set it is deliberately narrow.

#[derive(Deserialize)]
pub(crate) struct CreateOauthClientBody {
    client_name: String,
    #[serde(default)]
    client_uri: Option<String>,
    #[serde(default)]
    logo_uri: Option<String>,
    redirect_uris: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    confidential: bool,
    #[serde(default)]
    first_party: bool,
}

pub(crate) async fn create_oauth_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Json(body): Json<CreateOauthClientBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "oauth_admin").map_err(|_| AuthError::Forbidden)?;

    let (client, secret) = state
        .engine
        .create_oauth_client(surge_engine::oauth::NewOauthClient {
            client_name: body.client_name,
            client_uri: body.client_uri,
            logo_uri: body.logo_uri,
            redirect_uris: body.redirect_uris,
            grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
            scopes: body.scopes,
            confidential: body.confidential,
            first_party: body.first_party,
            registration_source: surge_engine::oauth::RegistrationSource::Admin,
        })
        .await?;

    state
        .engine
        .audit(
            surge_engine::audit::AuditActor::Service {
                id: auth.service_id.to_string(),
                name: auth.service_name,
            },
            "create_oauth_client",
            json!({"client_id": client.client_id, "first_party": client.first_party}),
            None,
        )
        .await?;

    let mut value = serde_json::to_value(&client).unwrap();
    // The secret leaves the engine exactly once, here.
    if let Some(secret) = secret {
        value["client_secret"] = json!(secret.expose_secret());
    }

    Ok((axum::http::StatusCode::CREATED, Json(value)))
}

pub(crate) async fn list_oauth_clients(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "oauth_admin").map_err(|_| AuthError::Forbidden)?;

    let clients = state.engine.list_oauth_clients().await?;
    Ok(Json(json!({ "clients": clients })))
}

pub(crate) async fn revoke_oauth_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Path(client_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "oauth_admin").map_err(|_| AuthError::Forbidden)?;

    state.engine.revoke_oauth_client(&client_id).await?;

    state
        .engine
        .audit(
            surge_engine::audit::AuditActor::Service {
                id: auth.service_id.to_string(),
                name: auth.service_name,
            },
            "revoke_oauth_client",
            json!({ "client_id": client_id }),
            None,
        )
        .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub(crate) struct CreateOauthResourceBody {
    resource_uri: String,
    scopes: Vec<String>,
    #[serde(default)]
    scope_descriptions: Option<serde_json::Value>,
}

/// A service registers its *own* audience. It cannot register one on behalf
/// of another service — the owning `service_id` is taken from the
/// authenticated token, not from the body — which is what keeps the
/// introspection authorization check meaningful.
pub(crate) async fn create_oauth_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Json(body): Json<CreateOauthResourceBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "oauth_admin").map_err(|_| AuthError::Forbidden)?;

    let resource = state
        .engine
        .create_oauth_resource(
            &body.resource_uri,
            auth.service_id,
            body.scopes,
            body.scope_descriptions
                .unwrap_or_else(|| json!({})),
        )
        .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::to_value(&resource).unwrap()),
    ))
}

pub(crate) async fn list_oauth_resources(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "oauth_admin").map_err(|_| AuthError::Forbidden)?;

    let resources = state.engine.list_oauth_resources().await?;
    Ok(Json(json!({ "resources": resources })))
}
