//! Service-facing API (v1).
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::json;
use surge_engine::oauth::{
    DeleteOutcome, OauthResource, ResourceManager, ResourcePatch, ResourceSource,
};
use surge_engine::types::*;
use uuid::Uuid;

use super::AppState;
use super::error::ApiError;
use super::middleware::{ServiceAuth, require_grant, service_auth};

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/sessions/verify", post(verify_session))
        .route("/sessions/resolve-browser", post(resolve_browser))
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
            get(identity_links)
                .post(link_identity)
                .delete(unlink_identity),
        )
        .route(
            "/oauth/clients",
            get(list_oauth_clients).post(create_oauth_client),
        )
        .route("/oauth/clients/{client_id}", delete(revoke_oauth_client))
        .route(
            "/oauth/resources",
            get(list_oauth_resources).post(create_oauth_resource),
        )
        // One path segment: a registration ID (GET) or a canonical URI
        // percent-encoded as a single segment (GET, PATCH, DELETE).
        .route(
            "/oauth/resources/{resource}",
            get(get_oauth_resource)
                .patch(update_oauth_resource)
                .delete(delete_oauth_resource),
        )
        .layer(middleware::from_fn_with_state(state.clone(), service_auth))
        .with_state(state)
}

#[derive(Deserialize)]
pub(crate) struct TokenBody {
    token: String,
}

#[derive(Deserialize)]
struct BrowserResolutionBody {
    token: String,
    account_id: Option<uuid::Uuid>,
}

async fn resolve_browser(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Json(body): Json<BrowserResolutionBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "introspect").map_err(|_| AuthError::Forbidden)?;
    let token = BrowserSessionToken::from_raw(&body.token).ok_or(AuthError::InvalidToken)?;
    let (account_id, session) = state
        .provider
        .resolve_browser_session(&token, body.account_id)
        .await?;
    audit_introspection(&state, auth, "resolve_browser_session", session.id).await?;
    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(json!({ "account_id": account_id, "session": session })),
    ))
}

pub(crate) async fn verify_session(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Json(body): Json<TokenBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "introspect").map_err(|_| AuthError::Forbidden)?;

    let token = SessionToken::from_raw(&body.token).ok_or(AuthError::InvalidToken)?;
    let session = state.provider.verify_session(Some(token)).await?;

    audit_introspection(&state, auth, "verify_session", session.id).await?;

    Ok(Json(serde_json::to_value(&session).unwrap()))
}

async fn audit_introspection(
    state: &AppState,
    auth: ServiceAuth,
    action: &str,
    session_id: SessionId,
) -> Result<(), ApiError> {
    state
        .engine
        .audit(
            surge_engine::audit::AuditActor::Service {
                id: auth.service_id.to_string(),
                name: auth.service_name,
            },
            action,
            json!({"session_id": session_id.to_string()}),
            None,
        )
        .await?;
    Ok(())
}

pub(crate) async fn revoke_session(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Json(body): Json<TokenBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_grant(&auth, "revoke").map_err(|_| AuthError::Forbidden)?;

    let token = SessionToken::from_raw(&body.token).ok_or(AuthError::InvalidToken)?;
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
#[serde(deny_unknown_fields)]
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
    /// Resources the client is approved for. Absent means no list.
    #[serde(default)]
    resources: Option<Vec<String>>,
}

/// How a caller may register a client. `oauth_admin` is trusted
/// administration. `oauth_client_register` is the Platform's separately
/// bounded authority: it can only mint third-party clients, and only ones
/// approved for resources that same service registered as a delegated
/// registrar. The Platform variant carries the registration IDs that passed
/// this check; the engine re-checks them under lock when it binds them.
enum ClientAuthority {
    Admin,
    Platform(Vec<Uuid>),
}

async fn authorize_client_registration(
    state: &AppState,
    auth: &ServiceAuth,
    body: &CreateOauthClientBody,
) -> Result<ClientAuthority, AuthError> {
    if require_grant(auth, "oauth_admin").is_ok() {
        return Ok(ClientAuthority::Admin);
    }
    require_grant(auth, "oauth_client_register").map_err(|_| AuthError::Forbidden)?;
    if body.first_party {
        return Err(AuthError::Forbidden);
    }
    let resources = body.resources.as_deref().unwrap_or_default();
    if resources.is_empty() {
        return Err(AuthError::Validation(ValidationError::Field {
            field: "resources",
            message: "a delegated registrar must name the resources the client is for".into(),
        }));
    }
    if resources.len() > surge_engine::oauth::MAX_PLATFORM_RESOURCES {
        return Err(AuthError::Validation(ValidationError::Field {
            field: "resources",
            message: format!(
                "at most {} resources are allowed",
                surge_engine::oauth::MAX_PLATFORM_RESOURCES
            ),
        }));
    }
    let mut ids = Vec::with_capacity(resources.len());
    for uri in resources {
        let resource = state
            .engine
            .get_oauth_resource(uri)
            .await
            .map_err(|e| match e {
                // An unknown resource and another registrar's look the same.
                AuthError::NotFound => AuthError::Forbidden,
                other => other,
            })?;
        if !ResourceAuthority::Registrar(auth.service_id).can_manage(&resource) {
            return Err(AuthError::Forbidden);
        }
        ids.push(resource.registration_id);
    }
    Ok(ClientAuthority::Platform(ids))
}

pub(crate) async fn create_oauth_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Json(body): Json<CreateOauthClientBody>,
) -> Result<impl IntoResponse, ApiError> {
    let authority = authorize_client_registration(&state, &auth, &body).await?;

    let spec = surge_engine::oauth::NewOauthClient {
        client_name: body.client_name,
        client_uri: body.client_uri,
        logo_uri: body.logo_uri,
        redirect_uris: body.redirect_uris,
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        scopes: body.scopes,
        confidential: body.confidential,
        first_party: body.first_party,
        registration_source: surge_engine::oauth::RegistrationSource::Admin,
        audiences: body.resources,
    };
    let (client, secret) = match authority {
        ClientAuthority::Admin => state.engine.create_oauth_client(spec).await?,
        ClientAuthority::Platform(ids) => {
            state
                .engine
                .create_platform_oauth_client(auth.service_id, spec, ids)
                .await?
        }
    };

    state
        .engine
        .audit(
            surge_engine::audit::AuditActor::Service {
                id: auth.service_id.to_string(),
                name: auth.service_name.clone(),
            },
            "create_oauth_client",
            json!({
                "client_id": client.client_id,
                "first_party": client.first_party,
                "registration_source": client.registration_source,
                "registrar_service_id": client.registrar_service_id,
                "resources": client.audiences,
            }),
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

/// Who a service is when it touches the audience registry.
///
/// `oauth_admin` is trusted administration: any registration, including
/// legacy ones whose registrar is unknown, and the only way to create a
/// service registration or name an owner. `oauth_resource_register` is the
/// Platform grant: it creates delegated resources and sees or manages only
/// those it registered itself. The registrar is always the authenticated
/// service, never a request field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResourceAuthority {
    Admin,
    Registrar(Uuid),
}

impl ResourceAuthority {
    pub(crate) fn of(auth: &ServiceAuth) -> Result<Self, AuthError> {
        if require_grant(auth, "oauth_admin").is_ok() {
            Ok(Self::Admin)
        } else if require_grant(auth, "oauth_resource_register").is_ok() {
            Ok(Self::Registrar(auth.service_id))
        } else {
            Err(AuthError::Forbidden)
        }
    }

    /// Whether this authority may read or change a registration. A
    /// registrar owns only delegated registrations it created; one with an
    /// unknown registrar, or another's, is administration's alone.
    pub(crate) fn can_manage(self, resource: &OauthResource) -> bool {
        self.manager().can_manage(resource)
    }

    pub(crate) fn manager(self) -> ResourceManager {
        match self {
            Self::Admin => ResourceManager::Admin,
            Self::Registrar(id) => ResourceManager::Registrar(id),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateOauthResourceBody {
    resource_uri: String,
    owner_service_id: Option<Uuid>,
    /// `service` (the default, for existing administrators) or `delegated`.
    #[serde(default)]
    registration_source: Option<ResourceSource>,
    scopes: Vec<String>,
    #[serde(default)]
    scope_descriptions: Option<serde_json::Value>,
    #[serde(default)]
    cimd_open: bool,
}

pub(crate) async fn create_oauth_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Json(body): Json<CreateOauthResourceBody>,
) -> Result<impl IntoResponse, ApiError> {
    let authority = ResourceAuthority::of(&auth)?;
    let source = body.registration_source.unwrap_or(match authority {
        ResourceAuthority::Admin => ResourceSource::Service,
        ResourceAuthority::Registrar(_) => ResourceSource::Delegated,
    });
    let owner = match (authority, source) {
        (ResourceAuthority::Admin, ResourceSource::Service) => {
            Some(body.owner_service_id.unwrap_or(auth.service_id))
        }
        // A delegated resource belongs to no service.
        (_, ResourceSource::Delegated) => {
            if body.owner_service_id.is_some() {
                return Err(match authority {
                    ResourceAuthority::Admin => AuthError::Validation(ValidationError::Field {
                        field: "owner_service_id",
                        message: "a delegated resource has no owning service".into(),
                    }),
                    ResourceAuthority::Registrar(_) => AuthError::Forbidden,
                }
                .into());
            }
            None
        }
        (_, ResourceSource::UserInfo | ResourceSource::Unknown) => {
            return Err(AuthError::Validation(ValidationError::Field {
                field: "registration_source",
                message: "must be `service` or `delegated`".into(),
            })
            .into());
        }
        // Service registrations and owner assignment stay with administration.
        (ResourceAuthority::Registrar(_), ResourceSource::Service) => {
            return Err(AuthError::Forbidden.into());
        }
    };

    let resource = state
        .engine
        .register_oauth_resource_with_cimd(
            surge_engine::audit::AuditActor::Service {
                id: auth.service_id.to_string(),
                name: auth.service_name,
            },
            auth.service_id,
            &body.resource_uri,
            owner,
            body.scopes,
            body.scope_descriptions.unwrap_or_else(|| json!({})),
            body.cimd_open,
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
    let resources = match ResourceAuthority::of(&auth)? {
        ResourceAuthority::Admin => state.engine.list_oauth_resources().await?,
        ResourceAuthority::Registrar(id) => state
            .engine
            .oauth_resources_for_registrar(id)
            .await?
            .into_iter()
            .filter(|r| ResourceAuthority::Registrar(id).can_manage(r))
            .collect(),
    };
    Ok(Json(json!({ "resources": resources })))
}

/// A path segment naming a registration: its ID, or its canonical URI
/// (percent-encoded into one segment; the extractor has already decoded it).
enum ResourceKey {
    Id(Uuid),
    Uri(String),
}

impl ResourceKey {
    fn parse(segment: String) -> Self {
        match Uuid::parse_str(&segment) {
            Ok(id) => Self::Id(id),
            Err(_) => Self::Uri(segment),
        }
    }
}

pub(crate) async fn get_oauth_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Path(resource): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let authority = ResourceAuthority::of(&auth)?;
    let resource = match ResourceKey::parse(resource) {
        ResourceKey::Id(id) => state.engine.get_oauth_registration(id).await?,
        ResourceKey::Uri(uri) => state.engine.get_oauth_resource(&uri).await?,
    };
    // Another registrar's resource is indistinguishable from a missing one.
    if !authority.can_manage(&resource) {
        return Err(AuthError::NotFound.into());
    }
    Ok(Json(serde_json::to_value(&resource).unwrap()))
}

fn audit_actor(auth: &ServiceAuth) -> surge_engine::audit::AuditActor {
    surge_engine::audit::AuditActor::Service {
        id: auth.service_id.to_string(),
        name: auth.service_name.clone(),
    }
}

/// `?registration_id=` and/or `If-Match: "<registration id>"`: the
/// registration the caller means. When both are given they must agree.
#[derive(Deserialize)]
pub(crate) struct PreconditionQuery {
    registration_id: Option<Uuid>,
}

fn precondition(query: &PreconditionQuery, headers: &HeaderMap) -> Result<Option<Uuid>, AuthError> {
    let bad = |message: &str| {
        AuthError::Validation(ValidationError::Field {
            field: "If-Match",
            message: message.into(),
        })
    };
    let header = match headers.get(axum::http::header::IF_MATCH) {
        None => None,
        Some(value) => {
            let value = value.to_str().map_err(|_| bad("not a registration id"))?;
            let id = value.trim().trim_matches('"');
            Some(Uuid::parse_str(id).map_err(|_| bad("must be a registration id"))?)
        }
    };
    match (query.registration_id, header) {
        (Some(a), Some(b)) if a != b => Err(AuthError::Validation(ValidationError::Field {
            field: "registration_id",
            message: "the query parameter and If-Match name different registrations".into(),
        })),
        (a, b) => Ok(a.or(b)),
    }
}

/// A lifecycle request names a registration by canonical URI only. A
/// registration ID in the path is refused rather than guessed at: the URI is
/// what a retry can re-derive, and the ID travels as the precondition.
fn lifecycle_uri(segment: String) -> Result<String, AuthError> {
    match ResourceKey::parse(segment) {
        ResourceKey::Uri(uri) => Ok(uri),
        ResourceKey::Id(_) => Err(AuthError::Validation(ValidationError::Field {
            field: "resource",
            message: "address the registration by its canonical URI; pass the registration id \
                      as registration_id or If-Match"
                .into(),
        })),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateOauthResourceBody {
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    scope_descriptions: Option<serde_json::Value>,
    #[serde(default)]
    allowed_cimd_client_ids: Option<Vec<String>>,
    #[serde(default)]
    cimd_open: Option<bool>,
    #[serde(default)]
    dcr_enabled: Option<bool>,
}

pub(crate) async fn update_oauth_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Path(resource): Path<String>,
    Query(query): Query<PreconditionQuery>,
    headers: HeaderMap,
    Json(body): Json<UpdateOauthResourceBody>,
) -> Result<impl IntoResponse, ApiError> {
    let authority = ResourceAuthority::of(&auth)?;
    let uri = lifecycle_uri(resource)?;
    let updated = state
        .engine
        .update_oauth_resource(
            audit_actor(&auth),
            authority.manager(),
            &uri,
            precondition(&query, &headers)?,
            ResourcePatch {
                scopes: body.scopes,
                scope_descriptions: body.scope_descriptions,
                allowed_cimd_client_ids: body.allowed_cimd_client_ids,
                cimd_open: body.cimd_open,
                dcr_enabled: body.dcr_enabled,
            },
        )
        .await?;
    Ok(Json(serde_json::to_value(&updated).unwrap()))
}

pub(crate) async fn delete_oauth_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<ServiceAuth>,
    Path(resource): Path<String>,
    Query(query): Query<PreconditionQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let authority = ResourceAuthority::of(&auth)?;
    let uri = lifecycle_uri(resource)?;
    let expected = precondition(&query, &headers)?;
    // A registrar's delete must name the registration it means: the Platform
    // retries deletions, possibly after the reservation has lapsed and
    // someone has registered the URI again, and a delete by URI alone would
    // take that successor down.
    if expected.is_none() && matches!(authority, ResourceAuthority::Registrar(_)) {
        return Err(AuthError::Validation(ValidationError::Field {
            field: "registration_id",
            message: "a registrar must name the registration to delete \
                      (registration_id or If-Match)"
                .into(),
        })
        .into());
    }
    let outcome = state
        .engine
        .delete_oauth_resource(
            audit_actor(&auth),
            authority.manager(),
            &uri,
            expected,
            state.oauth_access_ttl,
        )
        .await?;
    Ok(match outcome {
        DeleteOutcome::Deleted(_) | DeleteOutcome::AlreadyDeleted => {
            axum::http::StatusCode::NO_CONTENT
        }
    })
}
