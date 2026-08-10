use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
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
use super::trusted_proxy::{trusted_proxy, TrustedClientIp, TrustedProxyState};
use crate::extract::require_header_csrf;
use crate::traits::AuthProvider;
use crate::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationMode {
    Open,
    Invite,
    Closed,
}

/// Server-wide expectation of which factors a user should have enrolled. A
/// *soft recommendation* — it never blocks login or registration; it is
/// surfaced in login/register/whoami responses (the `policy` block) so the
/// frontend can prompt for enrollment. `Both` means "enroll both TOTP and a
/// passphrase"; login still needs only the password (plus TOTP if enrolled).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactorPolicy {
    None,
    Totp,
    Passphrase,
    Both,
}

impl FactorPolicy {
    /// `(totp_required, passphrase_required)`.
    pub fn requires(self) -> (bool, bool) {
        match self {
            FactorPolicy::None => (false, false),
            FactorPolicy::Totp => (true, false),
            FactorPolicy::Passphrase => (false, true),
            FactorPolicy::Both => (true, true),
        }
    }
}

/// Browser-router configuration. Common fields are always required.
/// Embedded-only fields are `Option` — required when the provider runs
/// handlers locally (`EmbeddedProvider`), ignored when it proxies to a
/// remote surge-server (`RemoteProvider`).
pub struct BrowserRouterConfig {
    pub cookie_domain: String,
    pub session_ttl: Duration,
    /// Origin the auth UI is served from. Sole allowed origin for the
    /// credential-entry zone, and the default for session-management when
    /// `session_cors_origins` is empty.
    pub auth_ui_origin: String,
    /// Origins allowed to call the session-management zone (`whoami`,
    /// `logout`, factors) with credentials. Leave empty to restrict that
    /// zone to `auth_ui_origin`; set it when your frontend is served from
    /// an origin other than the auth UI's (§8.2b).
    pub session_cors_origins: Vec<String>,

    // -- Embedded-only fields (ignored by RemoteProvider) --

    pub rate_limiter: Option<Arc<dyn RateLimiter>>,
    /// Origins `return_to` is allowed to target on `GET /login`.
    pub return_origins: Option<Vec<String>>,
    pub registration: Option<RegistrationMode>,
    /// Soft factor-enrollment policy surfaced to the frontend (never blocks).
    pub factor_policy: Option<FactorPolicy>,
    /// Enables content-negotiated flow-init on `GET /login`: with
    /// `Accept: application/json`, return the flow inline as JSON instead of
    /// redirecting to `auth_ui_origin`. Required for served+inline
    /// (architecture.md §6).
    pub allow_inline: Option<bool>,
    /// Opt-in Hydra login/consent bridge (rfc.md).
    pub oauth_bridge: Option<super::OauthBridgeConfig>,
    /// How often to run the background sweep (session GC, flow expiry).
    /// `None` uses `DEFAULT_MAINTENANCE_INTERVAL`: mounting the router
    /// starts the sweep, because a mounted router with no sweep silently
    /// accumulates expired sessions and flows forever. `Duration::ZERO`
    /// opts out, for callers driving `router::spawn_maintenance`
    /// themselves. Ignored by `RemoteProvider`, whose upstream sweeps.
    pub maintenance_interval: Option<Duration>,
}

/// Default sweep cadence when `maintenance_interval` is left unset.
pub const DEFAULT_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15 * 60);

struct EmbeddedState {
    cookie_domain: String,
    session_ttl: Duration,
    auth_ui_origin: String,
    session_cors_origins: Vec<String>,
    rate_limiter: Arc<dyn RateLimiter>,
    return_origins: Vec<String>,
    registration: RegistrationMode,
    factor_policy: FactorPolicy,
    allow_inline: bool,
    engine: Arc<Engine>,
    provider: Arc<dyn AuthProvider>,
}

/// Builds the embedded browser router at `/v1`. Handlers run locally
/// against the provided Engine and AuthProvider.
pub(crate) fn embedded_browser_router(
    engine: Arc<Engine>,
    provider: Arc<dyn AuthProvider>,
    config: BrowserRouterConfig,
) -> Router {
    let oauth_bridge = config.oauth_bridge.clone();
    let state = Arc::new(EmbeddedState {
        auth_ui_origin: config.auth_ui_origin.clone(),
        session_cors_origins: config.session_cors_origins,
        cookie_domain: config.cookie_domain,
        session_ttl: config.session_ttl,
        rate_limiter: config.rate_limiter.expect("embedded mode requires rate_limiter"),
        return_origins: config.return_origins.unwrap_or_default(),
        registration: config.registration.unwrap_or(RegistrationMode::Closed),
        factor_policy: config.factor_policy.unwrap_or(FactorPolicy::None),
        allow_inline: config.allow_inline.unwrap_or(false),
        engine,
        provider: Arc::clone(&provider),
    });
    let mut v1 = V1Router::new(Arc::clone(&state)).into_router();
    if let Some(bridge_config) = oauth_bridge {
        v1 = v1.merge(super::oauth_bridge::router(
            Arc::clone(&provider),
            bridge_config,
        ));
    }

    // Outside both CORS zones: it resolves who the caller is on behalf of
    // before any handler reads a rate-limit key.
    let v1 = v1.layer(middleware::from_fn_with_state(
        Arc::new(TrustedProxyState::new(Arc::clone(&state.engine))),
        trusted_proxy,
    ));

    let interval = config
        .maintenance_interval
        .unwrap_or(DEFAULT_MAINTENANCE_INTERVAL);
    if !interval.is_zero() {
        spawn_maintenance(provider, interval);
    }

    Router::new().nest("/v1", v1)
}

/// Spawns the background maintenance sweep (session GC, flow expiry).
///
/// Mounting an embedded browser router already starts this; call it
/// directly only when driving the cadence yourself (paired with
/// `maintenance_interval: Some(Duration::ZERO)`), or when running a
/// provider with no router mounted on it at all.
pub fn spawn_maintenance(
    provider: Arc<dyn AuthProvider>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = provider.run_maintenance().await {
                warn!(error = %e, "surge maintenance sweep failed");
            }
        }
    })
}

/// The v1 browser-facing perimeter router — credential entry (login, flows)
/// and session management (whoami, logout), each with its own CORS zone.
struct V1Router {
    state: Arc<EmbeddedState>,
}

impl V1Router {
    fn new(state: Arc<EmbeddedState>) -> Self {
        Self { state }
    }

    fn into_router(self) -> Router {
        let credential_entry = Router::new()
            .route("/login", get(start_login))
            .route("/flows/{id}", get(get_flow))
            .route("/flows/{id}/password", post(submit_password))
            .route("/flows/{id}/totp", post(submit_totp))
            .route("/flows/{id}/passphrase", post(submit_passphrase))
            .route("/flows/{id}/recover", post(submit_recover))
            .route("/flows/{id}/register", post(submit_register))
            .layer(cors::narrow(&self.state.auth_ui_origin))
            .with_state(Arc::clone(&self.state));

        let session_cors = if self.state.session_cors_origins.is_empty() {
            cors::narrow(&self.state.auth_ui_origin)
        } else {
            cors::union(&self.state.session_cors_origins)
        };

        let csrf = || middleware::from_fn(require_header_csrf);
        let session_management = Router::new()
            .route("/whoami", get(whoami))
            .route(
                "/logout",
                post(logout).layer(csrf()),
            )
            .route("/factors", get(get_factors))
            .route("/factors/totp/enroll", post(enroll_totp).layer(csrf()))
            .route("/factors/totp/confirm", post(confirm_totp).layer(csrf()))
            .route("/factors/totp", delete(remove_totp).layer(csrf()))
            .route(
                "/factors/passphrase",
                post(enroll_passphrase).delete(remove_passphrase).layer(csrf()),
            )
            .route("/factors/passphrase/confirm", post(confirm_passphrase).layer(csrf()))
            .route("/account/password", post(change_password).layer(csrf()))
            .layer(session_cors)
            .with_state(self.state);

        Router::new()
            .merge(credential_entry)
            .merge(session_management)
    }
}

/// The address rate limiting is keyed on.
///
/// Prefers the end-user address stated by an authenticated proxy (see
/// `trusted_proxy`) — behind a `RemoteProvider` the peer address is the
/// service, and keying on it would put every one of that service's users
/// in a single bucket. Falls back to the peer address, which itself is
/// absent unless the server was bound via
/// `into_make_service_with_connect_info`; missing it must not fail the
/// request.
struct MaybeClientIp(Option<std::net::IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for MaybeClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let trusted = parts
            .extensions
            .get::<TrustedClientIp>()
            .map(|TrustedClientIp(ip)| *ip);

        Ok(Self(trusted.or_else(|| {
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip())
        })))
    }
}

#[derive(Deserialize)]
struct LoginQuery {
    return_to: Option<String>,
}

async fn start_login(
    State(state): State<Arc<EmbeddedState>>,
    Query(query): Query<LoginQuery>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    // Content-negotiated flow-init (architecture.md §7.4): a caller asking
    // for JSON gets the flow inline instead of a redirect. Gated behind
    // `allow_inline` because for a served (non-embedded) deployment this is
    // the served+inline combination (§6), which requires the operator's
    // explicit acknowledgment; plain browser navigation (no `Accept` header)
    // always gets the redirect regardless.
    let wants_json = state.allow_inline
        && headers
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("application/json"));

    // `return_to` is required for browser-navigation (redirect) logins,
    // since it's the only place the post-login destination is recorded —
    // there's no other channel for an unauthenticated redirect flow to
    // communicate it. It's optional in inline mode: an embedded caller on
    // that path manages its own post-login navigation and has no use for a
    // server-chosen destination.
    let return_to = match &query.return_to {
        Some(return_to) => {
            let return_url = url::Url::parse(return_to).map_err(|_| {
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

            let allowed = state.return_origins.iter().any(|o| o == &origin)
                || origin_with_port
                    .as_ref()
                    .is_some_and(|o| state.return_origins.contains(o));

            if !allowed {
                return Err(AuthError::Validation(ValidationError::Field {
                    field: "return_to",
                    message: "origin not registered".into(),
                })
                .into());
            }

            Some(return_to.as_str())
        }
        None if wants_json => None,
        None => {
            return Err(AuthError::Validation(ValidationError::Field {
                field: "return_to",
                message: "required".into(),
            })
            .into());
        }
    };

    let flow = state.engine.create_login_flow(return_to).await?;

    if wants_json {
        return Ok(Json(json!({
            "flow_id": flow.id,
            "csrf_token": flow.csrf_token,
            "registration_mode": match state.registration {
                RegistrationMode::Open => "open",
                RegistrationMode::Invite => "invite",
                RegistrationMode::Closed => "closed",
            },
        }))
        .into_response());
    }

    let redirect_url = format!("{}/login?flow={}", state.auth_ui_origin, flow.id);
    Ok(Redirect::to(&redirect_url).into_response())
}

async fn get_flow(
    State(state): State<Arc<EmbeddedState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let flow = state.engine.get_login_flow(&id).await?;

    Ok(Json(json!({
        "id": flow.id,
        "state": flow.state,
        "csrf_token": flow.csrf_token,
        "error": flow.error,
        "registration_enabled": state.registration != RegistrationMode::Closed,
    })))
}

#[derive(Deserialize)]
struct PasswordSubmit {
    username: String,
    password: String,
    csrf_token: String,
}

async fn submit_password(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    Path(id): Path<String>,
    Json(body): Json<PasswordSubmit>,
) -> Result<Response, ApiError> {
    let flow = state.engine.get_login_flow(&id).await?;

    if flow.state != "created" {
        return Err(AuthError::InvalidToken.into());
    }
    check_flow_csrf(&flow.csrf_token, &body.csrf_token)?;

    state.rate_limiter.check("flow", "flow_submit", ip, None).await?;

    let username = match Username::new(&body.username) {
        Ok(u) => u,
        Err(_) => {
            state.engine.record_flow_error(&id, "invalid_credentials").await?;
            return Err(AuthError::InvalidCredentials.into());
        }
    };

    state
        
        .rate_limiter
        .check("flow", "authenticate", ip, Some(username.as_str()))
        .await?;

    let password = match Password::new(SecretString::from(body.password)) {
        Ok(p) => p,
        Err(_) => {
            state.engine.record_flow_error(&id, "invalid_credentials").await?;
            return Err(AuthError::InvalidCredentials.into());
        }
    };

    // Split verify from mint (unlike `provider.authenticate_password`, which
    // bundles verify+mint+audit): a user with a confirmed TOTP must clear the
    // second step before any session is minted.
    let identity = match state.engine.verify_credential(&username, &password).await {
        Ok(identity) => identity,
        Err(e) => {
            state.engine.record_flow_error(&id, "invalid_credentials").await?;
            return Err(e.into());
        }
    };

    if state.engine.has_totp(identity.id).await? {
        state
            .engine
            .set_flow_awaiting_totp(&id, identity.id)
            .await?;
        return Ok(Json(json!({
            "status": "totp_required",
            "return_to": flow.return_to,
        }))
        .into_response());
    }

    finish_login(
        &state,
        &id,
        flow.return_to,
        identity.id,
        "authenticate",
        json!({ "factors": ["password"] }),
    )
    .await
}

/// Shared tail of every login path: mint the session (always recorded as
/// `authenticated_via = password` — factor specifics go to the audit log so
/// the session-introspection wire contract stays append-only), audit, complete
/// the flow, set the cookie, and return the session plus the policy block.
async fn finish_login(
    state: &EmbeddedState,
    flow_id: &str,
    return_to: Option<String>,
    identity_id: IdentityId,
    audit_action: &str,
    audit_detail: serde_json::Value,
) -> Result<Response, ApiError> {
    let issued = state
        .engine
        .mint_session(identity_id, AuthMethod::Password)
        .await?;

    state
        .engine
        .audit(
            surge_engine::audit::AuditActor::Identity {
                id: identity_id.to_string(),
            },
            audit_action,
            json!({ "session_id": issued.session.id.to_string() }),
            Some(audit_detail),
        )
        .await?;

    state.engine.complete_flow(flow_id).await?;

    let cookie = session_cookie(
        issued.token.expose_secret(),
        &state.cookie_domain,
        state.session_ttl.as_secs() as i64,
    );
    let jar = CookieJar::new().add(cookie);
    let policy = policy_block(&state, identity_id).await?;

    Ok((
        jar,
        Json(json!({
            "return_to": return_to,
            "session": serde_json::to_value(&issued.session).unwrap(),
            "policy": policy,
        })),
    )
        .into_response())
}

/// The soft-policy compliance block surfaced to the frontend.
async fn policy_block(
    state: &EmbeddedState,
    identity_id: IdentityId,
) -> Result<serde_json::Value, AuthError> {
    let status = state.engine.factor_status(identity_id).await?;
    let (totp_required, passphrase_required) = state.factor_policy.requires();
    let compliant =
        (!totp_required || status.has_totp) && (!passphrase_required || status.has_passphrase);

    Ok(json!({
        "required": { "totp": totp_required, "passphrase": passphrase_required },
        "has": { "totp": status.has_totp, "passphrase": status.has_passphrase },
        "compliant": compliant,
    }))
}

#[derive(Deserialize)]
struct TotpSubmit {
    code: String,
    csrf_token: String,
}

/// Mandatory second step after password when TOTP is enrolled.
async fn submit_totp(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    Path(id): Path<String>,
    Json(body): Json<TotpSubmit>,
) -> Result<Response, ApiError> {
    let flow = state.engine.get_login_flow(&id).await?;
    if flow.state != "awaiting_totp" {
        return Err(AuthError::InvalidToken.into());
    }
    check_flow_csrf(&flow.csrf_token, &body.csrf_token)?;
    let identity_id = flow.identity_id.ok_or(AuthError::InvalidToken)?;

    state.rate_limiter.check("flow", "flow_submit", ip, None).await?;
    // Per-identity limit is the real brute-force control here: the flow's
    // attempt cap bounds nothing across freshly-created flows.
    state
        
        .rate_limiter
        .check("flow", "authenticate", ip, Some(&identity_id.to_string()))
        .await?;

    match state.engine.verify_totp(identity_id, &body.code).await {
        Ok(()) => {
            finish_login(
                &state,
                &id,
                flow.return_to,
                identity_id,
                "authenticate",
                json!({ "factors": ["password", "totp"] }),
            )
            .await
        }
        Err(e) => {
            state.engine.record_flow_error(&id, "invalid_totp").await?;
            Err(e.into())
        }
    }
}

#[derive(Deserialize)]
struct PassphraseLogin {
    username: String,
    passphrase: String,
    csrf_token: String,
}

/// Standalone passphrase login — bypasses password and TOTP entirely.
async fn submit_passphrase(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    Path(id): Path<String>,
    Json(body): Json<PassphraseLogin>,
) -> Result<Response, ApiError> {
    let flow = state.engine.get_login_flow(&id).await?;
    if flow.state != "created" {
        return Err(AuthError::InvalidToken.into());
    }
    check_flow_csrf(&flow.csrf_token, &body.csrf_token)?;

    state.rate_limiter.check("flow", "flow_submit", ip, None).await?;

    let username = match Username::new(&body.username) {
        Ok(u) => u,
        Err(_) => {
            state.engine.record_flow_error(&id, "invalid_credentials").await?;
            return Err(AuthError::InvalidCredentials.into());
        }
    };
    state
        
        .rate_limiter
        .check("flow", "authenticate", ip, Some(username.as_str()))
        .await?;

    match state
        .engine
        .verify_passphrase_by_username(&username, &body.passphrase)
        .await
    {
        Ok(identity) => {
            finish_login(
                &state,
                &id,
                flow.return_to,
                identity.id,
                "passphrase_login",
                json!({ "factors": ["passphrase"] }),
            )
            .await
        }
        Err(e) => {
            state.engine.record_flow_error(&id, "invalid_credentials").await?;
            Err(e.into())
        }
    }
}

#[derive(Deserialize)]
struct RecoverSubmit {
    username: String,
    passphrase: String,
    new_password: String,
    csrf_token: String,
}

/// Unauthenticated password recovery, authorized by the passphrase.
async fn submit_recover(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    Path(id): Path<String>,
    Json(body): Json<RecoverSubmit>,
) -> Result<Response, ApiError> {
    let flow = state.engine.get_login_flow(&id).await?;
    if flow.state != "created" {
        return Err(AuthError::InvalidToken.into());
    }
    check_flow_csrf(&flow.csrf_token, &body.csrf_token)?;

    state.rate_limiter.check("flow", "flow_submit", ip, None).await?;

    let username = match Username::new(&body.username) {
        Ok(u) => u,
        Err(_) => {
            state.engine.record_flow_error(&id, "invalid_credentials").await?;
            return Err(AuthError::InvalidCredentials.into());
        }
    };
    state
        
        .rate_limiter
        .check("flow", "authenticate", ip, Some(username.as_str()))
        .await?;

    // Validate the new password before touching the passphrase oracle.
    let new_password = Password::new(SecretString::from(body.new_password))
        .map_err(|e| AuthError::Validation(ValidationError::from(e)))?;

    match state
        .engine
        .verify_passphrase_by_username(&username, &body.passphrase)
        .await
    {
        Ok(identity) => {
            state.engine.set_password(identity.id, &new_password).await?;
            finish_login(
                &state,
                &id,
                flow.return_to,
                identity.id,
                "password_reset",
                json!({ "factors": ["passphrase"] }),
            )
            .await
        }
        Err(e) => {
            state.engine.record_flow_error(&id, "invalid_credentials").await?;
            Err(e.into())
        }
    }
}

/// Resolve the logged-in identity from the `surge_session` cookie (mirrors
/// `whoami`). Used by the authenticated factor-management endpoints.
async fn require_session(state: &EmbeddedState, jar: &CookieJar) -> Result<Session, ApiError> {
    let cookie = jar.get("surge_session").ok_or(AuthError::InvalidToken)?;
    let token = SessionToken::from_raw(cookie.value()).ok_or(AuthError::InvalidToken)?;
    Ok(state.provider.verify_session(Some(token)).await?)
}

/// Per-identity throttle for step-up-guarded mutations. A valid session is
/// required to reach these, but the `step_up` secret still shouldn't be
/// brute-forceable from a stolen session.
async fn rate_limit_step_up(
    state: &EmbeddedState,
    ip: Option<std::net::IpAddr>,
    id: IdentityId,
) -> Result<(), ApiError> {
    state
        
        .rate_limiter
        .check("account", "authenticate", ip, Some(&id.to_string()))
        .await?;
    Ok(())
}

#[derive(Deserialize)]
struct StepUp {
    step_up: String,
}

#[derive(Deserialize)]
struct ChangePassword {
    step_up: String,
    new_password: String,
}

async fn get_factors(
    State(state): State<Arc<EmbeddedState>>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &jar).await?;
    let policy = policy_block(&state, session.identity.id).await?;
    Ok(Json(json!({ "policy": policy })).into_response())
}

async fn enroll_totp(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    jar: CookieJar,
    Json(body): Json<StepUp>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &jar).await?;
    let id = session.identity.id;
    rate_limit_step_up(&state, ip, id).await?;
    state.engine.verify_step_up(id, &body.step_up).await?;

    let enrollment = state.engine.begin_totp_enrollment(id).await?;
    Ok(Json(json!({
        "otpauth_uri": enrollment.otpauth_uri,
        "secret": enrollment.secret_base32,
    }))
    .into_response())
}

#[derive(Deserialize)]
struct ConfirmTotp {
    code: String,
}

async fn confirm_totp(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    jar: CookieJar,
    Json(body): Json<ConfirmTotp>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &jar).await?;
    let id = session.identity.id;
    rate_limit_step_up(&state, ip, id).await?;
    state.engine.confirm_totp(id, &body.code).await?;
    state
        .engine
        .audit(
            surge_engine::audit::AuditActor::Identity { id: id.to_string() },
            "totp_enrolled",
            json!({ "identity_id": id.to_string() }),
            None,
        )
        .await?;
    let policy = policy_block(&state, id).await?;
    Ok(Json(json!({ "policy": policy })).into_response())
}

async fn remove_totp(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    jar: CookieJar,
    Json(body): Json<StepUp>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &jar).await?;
    let id = session.identity.id;
    rate_limit_step_up(&state, ip, id).await?;
    state.engine.verify_step_up(id, &body.step_up).await?;
    state.engine.remove_totp(id).await?;
    let policy = policy_block(&state, id).await?;
    Ok(Json(json!({ "policy": policy })).into_response())
}

async fn enroll_passphrase(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    jar: CookieJar,
    Json(body): Json<StepUp>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &jar).await?;
    let id = session.identity.id;
    rate_limit_step_up(&state, ip, id).await?;
    state.engine.verify_step_up(id, &body.step_up).await?;
    let passphrase = state.engine.begin_passphrase_enrollment(id).await?;
    Ok(Json(json!({ "passphrase": passphrase })).into_response())
}

#[derive(Deserialize)]
struct ConfirmPassphrase {
    passphrase: String,
}

async fn confirm_passphrase(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    jar: CookieJar,
    Json(body): Json<ConfirmPassphrase>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &jar).await?;
    let id = session.identity.id;
    rate_limit_step_up(&state, ip, id).await?;
    state.engine.confirm_passphrase(id, &body.passphrase).await?;
    let policy = policy_block(&state, id).await?;
    Ok(Json(json!({ "policy": policy })).into_response())
}

async fn remove_passphrase(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    jar: CookieJar,
    Json(body): Json<StepUp>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &jar).await?;
    let id = session.identity.id;
    rate_limit_step_up(&state, ip, id).await?;
    state.engine.verify_step_up(id, &body.step_up).await?;
    state.engine.remove_passphrase(id).await?;
    let policy = policy_block(&state, id).await?;
    Ok(Json(json!({ "policy": policy })).into_response())
}

async fn change_password(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    jar: CookieJar,
    Json(body): Json<ChangePassword>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &jar).await?;
    let id = session.identity.id;
    rate_limit_step_up(&state, ip, id).await?;
    state.engine.verify_step_up(id, &body.step_up).await?;

    let new_password = Password::new(SecretString::from(body.new_password))
        .map_err(|e| AuthError::Validation(ValidationError::from(e)))?;
    state.engine.set_password(id, &new_password).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
struct RegisterSubmit {
    username: String,
    password: String,
    display_name: String,
    csrf_token: String,
}

async fn submit_register(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    Path(id): Path<String>,
    Json(body): Json<RegisterSubmit>,
) -> Result<Response, ApiError> {
    match state.registration {
        RegistrationMode::Closed => return Err(AuthError::Forbidden.into()),
        RegistrationMode::Invite => {
            return Err(AuthError::Internal(anyhow::anyhow!(
                "invite-based registration is not yet implemented"
            ))
            .into());
        }
        RegistrationMode::Open => {}
    }

    let flow = state.engine.get_login_flow(&id).await?;
    if flow.state != "created" {
        return Err(AuthError::InvalidToken.into());
    }
    check_flow_csrf(&flow.csrf_token, &body.csrf_token)?;

    state.rate_limiter.check("flow", "flow_submit", ip, None).await?;
    state
        
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

    let issued = state.provider.register_and_authenticate(req).await?;

    state.engine.complete_flow(&id).await?;

    let cookie = session_cookie(
        issued.token.expose_secret(),
        &state.cookie_domain,
        state.session_ttl.as_secs() as i64,
    );
    let jar = CookieJar::new().add(cookie);
    // A fresh user is non-compliant the moment they register under any
    // non-`none` policy, so the frontend needs the block here too.
    let policy = policy_block(&state, issued.session.identity.id).await?;

    Ok((
        StatusCode::CREATED,
        jar,
        Json(json!({
            "return_to": flow.return_to,
            "session": serde_json::to_value(&issued.session).unwrap(),
            "policy": policy,
        })),
    )
        .into_response())
}

/// Browser->Surge session resolution: the frontend's "am I logged in, and
/// who am I?" call. Read-only, so no CSRF gate — it only inspects the
/// session cookie. Cross-origin callers need `session_cors_origins`
/// (§8.2b); same-origin frontends work with it empty.
async fn whoami(State(state): State<Arc<EmbeddedState>>, jar: CookieJar) -> Result<impl IntoResponse, ApiError> {
    let cookie = jar.get("surge_session").ok_or(AuthError::InvalidToken)?;
    let token = SessionToken::from_raw(cookie.value()).ok_or(AuthError::InvalidToken)?;
    let session = state.provider.verify_session(Some(token)).await?;
    let policy = policy_block(&state, session.identity.id).await?;
    let mut body = serde_json::to_value(&session).unwrap();
    body["policy"] = policy;
    Ok(Json(body))
}

async fn logout(State(state): State<Arc<EmbeddedState>>, jar: CookieJar) -> Result<Response, ApiError> {
    if let Some(cookie) = jar.get("surge_session") {
        if let Some(token) = SessionToken::from_raw(cookie.value()) {
            let _ = state.provider.revoke_session(&token).await;
        }
    }

    let removal = removal_cookie(&state.cookie_domain);
    let jar = CookieJar::new().add(removal);
    Ok((jar, StatusCode::NO_CONTENT).into_response())
}
