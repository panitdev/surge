use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
use surge_engine::Engine;
use tracing::warn;

use super::cookie::{removal_cookie, session_cookie};
use super::cors;
use super::csrf::check_flow_csrf;
use super::error::ApiError;
use super::rate_limit::RateLimiter;
use crate::extract::require_header_csrf;
use crate::traits::AuthProvider;
use crate::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationMode {
    Open,
    Invite,
    Closed,
}

/// A browser-facing API version this router knows how to serve. Grows
/// (additive, minor) the day a version ships; shrinks (major bump) the day
/// one is sunset — see architecture.md §3. Never a single `const VERSION`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiVersion {
    V1,
    V2,
}

impl ApiVersion {
    fn path(self) -> &'static str {
        match self {
            ApiVersion::V1 => "/v1",
            ApiVersion::V2 => "/v2",
        }
    }
}

/// Every version currently live and nested by [`BrowserRouter::into_axum`].
/// Sessions minted under any of these must remain readable by all of them
/// forever (architecture.md §2) — deleting an entry here is the sunset
/// major-bump, not a routine edit.
pub const SUPPORTED: &[ApiVersion] = &[ApiVersion::V1, ApiVersion::V2];

/// Configuration for the mountable browser perimeter router. `engine` and
/// `provider` are deliberately separate: `provider` is the trusted,
/// unthrottled `AuthProvider` surface (auth/register/verify/revoke), while
/// `engine` gives this router direct access to login-flow state and the
/// counter store — neither of which is part of `AuthProvider`, since a
/// `RemoteProvider` (which never mounts this router) has neither.
pub struct BrowserRouterConfig {
    pub engine: Arc<Engine>,
    pub provider: Arc<dyn AuthProvider>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub cookie_domain: String,
    pub session_ttl: Duration,
    /// Origin the auth UI is served from. Sole allowed origin for the
    /// credential-entry zone, and the default for session-management when
    /// `session_cors_origins` is empty. Also the redirect target for
    /// `GET /login`.
    pub auth_ui_origin: String,
    /// Non-empty enables the opt-in browser->Surge session-management
    /// zone: credentialed CORS over this union instead of the narrow
    /// same-origin default (§8.2b). Leave empty for the default,
    /// same-origin-only `/me` + `/logout` path (see `extract::me_logout_router`).
    pub session_cors_origins: Vec<String>,
    /// Origins `return_to` is allowed to target on `GET /login`.
    pub return_origins: Vec<String>,
    pub registration: RegistrationMode,
    /// Enables content-negotiated flow-init on `GET /login`: with
    /// `Accept: application/json`, return the flow inline as JSON instead of
    /// redirecting to `auth_ui_origin`. Required for served+inline
    /// (architecture.md §6) — leave `false` (the default posture for a
    /// served, non-embedded deployment) unless the operator has explicitly
    /// acknowledged the coarsened-rate-limiting tradeoff that comes with it.
    /// Embedded consumers, which have no such tradeoff, may set this `true`
    /// unconditionally.
    pub allow_inline: bool,
}

struct AppState {
    config: Arc<BrowserRouterConfig>,
}

pub struct BrowserRouter {
    config: Arc<BrowserRouterConfig>,
}

pub fn browser(config: BrowserRouterConfig) -> BrowserRouter {
    BrowserRouter {
        config: Arc::new(config),
    }
}

impl BrowserRouter {
    /// Spawns the background sweep (session GC, flow expiry) this router
    /// owns. A provider mounted without a router does none of this itself.
    pub fn spawn_maintenance(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let provider = Arc::clone(&self.config.provider);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = provider.run_maintenance().await {
                    warn!(error = %e, "surge maintenance sweep failed");
                }
            }
        })
    }

    /// Nests every version in [`SUPPORTED`] under its own path prefix, all
    /// live simultaneously in the one router this crate exports
    /// (architecture.md §3). There is no unprefixed default: a caller picks
    /// its version by which path it calls, and none of them are ever
    /// removed except at a major bump.
    pub fn into_axum(self) -> Router {
        let state = Arc::new(AppState {
            config: self.config,
        });

        SUPPORTED.iter().fold(Router::new(), |router, version| {
            router.nest(version.path(), Self::version_router(Arc::clone(&state)))
        })
    }

    fn version_router(state: Arc<AppState>) -> Router {
        let credential_entry = Router::new()
            .route("/login", get(start_login))
            .route("/flows/{id}", get(get_flow))
            .route("/flows/{id}/password", post(submit_password))
            .route("/flows/{id}/register", post(submit_register))
            .layer(cors::narrow(&state.config.auth_ui_origin))
            .with_state(Arc::clone(&state));

        let session_cors = if state.config.session_cors_origins.is_empty() {
            cors::narrow(&state.config.auth_ui_origin)
        } else {
            cors::union(&state.config.session_cors_origins)
        };

        let session_management = Router::new()
            .route("/whoami", get(whoami))
            .route(
                "/logout",
                post(logout).layer(middleware::from_fn(require_header_csrf)),
            )
            .layer(session_cors)
            .with_state(state);

        Router::new()
            .merge(credential_entry)
            .merge(session_management)
    }
}

/// `ConnectInfo<SocketAddr>` isn't present unless the server was bound via
/// `into_make_service_with_connect_info`; this extracts it if available
/// without failing the request when it isn't.
struct MaybeClientIp(Option<std::net::IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for MaybeClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip()),
        ))
    }
}

#[derive(Deserialize)]
struct LoginQuery {
    return_to: String,
}

async fn start_login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LoginQuery>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let return_url = url::Url::parse(&query.return_to).map_err(|_| {
        AuthError::Validation(ValidationError::Field {
            field: "return_to",
            message: "invalid URL".into(),
        })
    })?;

    let origin = format!(
        "{}://{}",
        return_url.scheme(),
        return_url.host_str().unwrap_or("")
    );
    let origin_with_port = return_url.port().map(|port| format!("{origin}:{port}"));

    let allowed = state.config.return_origins.iter().any(|o| o == &origin)
        || origin_with_port
            .as_ref()
            .is_some_and(|o| state.config.return_origins.contains(o));

    if !allowed {
        return Err(AuthError::Validation(ValidationError::Field {
            field: "return_to",
            message: "origin not registered".into(),
        })
        .into());
    }

    let flow = state.config.engine.create_login_flow(&query.return_to).await?;

    // Content-negotiated flow-init (architecture.md §7.4): a caller asking
    // for JSON gets the flow inline instead of a redirect. Gated behind
    // `allow_inline` because for a served (non-embedded) deployment this is
    // the served+inline combination (§6), which requires the operator's
    // explicit acknowledgment; plain browser navigation (no `Accept` header)
    // always gets the redirect regardless.
    let wants_json = state.config.allow_inline
        && headers
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("application/json"));

    if wants_json {
        return Ok(Json(json!({
            "flow_id": flow.id,
            "csrf_token": flow.csrf_token,
            "registration_mode": match state.config.registration {
                RegistrationMode::Open => "open",
                RegistrationMode::Invite => "invite",
                RegistrationMode::Closed => "closed",
            },
        }))
        .into_response());
    }

    let redirect_url = format!("{}/login?flow={}", state.config.auth_ui_origin, flow.id);
    Ok(Redirect::to(&redirect_url).into_response())
}

async fn get_flow(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let flow = state.config.engine.get_login_flow(&id).await?;

    Ok(Json(json!({
        "id": flow.id,
        "state": flow.state,
        "csrf_token": flow.csrf_token,
        "error": flow.error,
        "registration_enabled": state.config.registration != RegistrationMode::Closed,
    })))
}

#[derive(Deserialize)]
struct PasswordSubmit {
    username: String,
    password: String,
    csrf_token: String,
}

async fn submit_password(
    State(state): State<Arc<AppState>>,
    MaybeClientIp(ip): MaybeClientIp,
    Path(id): Path<String>,
    Json(body): Json<PasswordSubmit>,
) -> Result<Response, ApiError> {
    let flow = state.config.engine.get_login_flow(&id).await?;

    if flow.state != "created" {
        return Err(AuthError::InvalidToken.into());
    }
    check_flow_csrf(&flow.csrf_token, &body.csrf_token)?;

    state.config.rate_limiter.check("flow", "flow_submit", ip, None).await?;

    let username = match Username::new(&body.username) {
        Ok(u) => u,
        Err(_) => {
            state.config.engine.record_flow_error(&id, "invalid_credentials").await?;
            return Err(AuthError::InvalidCredentials.into());
        }
    };

    state
        .config
        .rate_limiter
        .check("flow", "authenticate", ip, Some(username.as_str()))
        .await?;

    let password = match Password::new(SecretString::from(body.password)) {
        Ok(p) => p,
        Err(_) => {
            state.config.engine.record_flow_error(&id, "invalid_credentials").await?;
            return Err(AuthError::InvalidCredentials.into());
        }
    };

    match state.config.provider.authenticate_password(&username, &password).await {
        Ok(issued) => {
            state.config.engine.complete_flow(&id).await?;

            let cookie = session_cookie(
                issued.token.expose_secret(),
                &state.config.cookie_domain,
                state.config.session_ttl.as_secs() as i64,
            );
            let jar = CookieJar::new().add(cookie);

            Ok((
                jar,
                Json(json!({
                    "return_to": flow.return_to,
                    "session": serde_json::to_value(&issued.session).unwrap(),
                })),
            )
                .into_response())
        }
        Err(e) => {
            state.config.engine.record_flow_error(&id, "invalid_credentials").await?;
            Err(e.into())
        }
    }
}

#[derive(Deserialize)]
struct RegisterSubmit {
    username: String,
    password: String,
    display_name: String,
    csrf_token: String,
}

async fn submit_register(
    State(state): State<Arc<AppState>>,
    MaybeClientIp(ip): MaybeClientIp,
    Path(id): Path<String>,
    Json(body): Json<RegisterSubmit>,
) -> Result<Response, ApiError> {
    match state.config.registration {
        RegistrationMode::Closed => return Err(AuthError::Forbidden.into()),
        RegistrationMode::Invite => {
            return Err(AuthError::Internal(anyhow::anyhow!(
                "invite-based registration is not yet implemented"
            ))
            .into());
        }
        RegistrationMode::Open => {}
    }

    let flow = state.config.engine.get_login_flow(&id).await?;
    if flow.state != "created" {
        return Err(AuthError::InvalidToken.into());
    }
    check_flow_csrf(&flow.csrf_token, &body.csrf_token)?;

    state.config.rate_limiter.check("flow", "flow_submit", ip, None).await?;
    state
        .config
        .rate_limiter
        .check("flow", "register", ip, None)
        .await?;

    let username = Username::new(&body.username)
        .map_err(|e| AuthError::Validation(ValidationError::from(e)))?;
    let password = Password::new(SecretString::from(body.password))
        .map_err(|e| AuthError::Validation(ValidationError::from(e)))?;

    let req = RegisterRequest {
        username,
        password,
        display_name: body.display_name,
    };

    let issued = state.config.provider.register_and_authenticate(req).await?;

    state.config.engine.complete_flow(&id).await?;

    let cookie = session_cookie(
        issued.token.expose_secret(),
        &state.config.cookie_domain,
        state.config.session_ttl.as_secs() as i64,
    );
    let jar = CookieJar::new().add(cookie);

    Ok((
        StatusCode::CREATED,
        jar,
        Json(json!({
            "return_to": flow.return_to,
            "session": serde_json::to_value(&issued.session).unwrap(),
        })),
    )
        .into_response())
}

/// Browser->Surge session resolution — the opt-in path (§8.2b), gated
/// behind credentialed `session_cors_origins`. Prefer
/// `extract::me_logout_router` (same-origin default) unless a Panit
/// service genuinely needs direct browser calls to Surge.
async fn whoami(State(state): State<Arc<AppState>>, jar: CookieJar) -> Result<impl IntoResponse, ApiError> {
    let cookie = jar.get("surge_session").ok_or(AuthError::InvalidToken)?;
    let token = SessionToken::from_raw(cookie.value()).ok_or(AuthError::InvalidToken)?;
    let session = state.config.provider.verify_session(&token).await?;
    Ok(Json(serde_json::to_value(&session).unwrap()))
}

async fn logout(State(state): State<Arc<AppState>>, jar: CookieJar) -> Result<Response, ApiError> {
    if let Some(cookie) = jar.get("surge_session") {
        if let Some(token) = SessionToken::from_raw(cookie.value()) {
            let _ = state.config.provider.revoke_session(&token).await;
        }
    }

    let removal = removal_cookie(&state.config.cookie_domain);
    let jar = CookieJar::new().add(removal);
    Ok((jar, StatusCode::NO_CONTENT).into_response())
}
