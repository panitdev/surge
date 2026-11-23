use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
use surge_engine::{Engine, VerifiedLogin};
use tracing::warn;

use super::cookie::{removal_cookie, session_cookie};
use super::cors;
use super::csrf::check_flow_csrf;
use super::error::ApiError;
use super::rate_limit::RateLimiter;
use super::trusted_proxy::{trusted_proxy, TrustedClientIp, TrustedProxyState};
use crate::extract::{browser_cookie, require_header_csrf, resolve_request_parts, ResolvedSession, ACCOUNT_HEADER};
use crate::traits::AuthProvider;
use crate::*;

fn legacy_cookie(headers: &HeaderMap) -> Option<SessionToken> {
    CookieJar::from_headers(headers).get("surge_session")
        .and_then(|cookie| SessionToken::from_raw(cookie.value()))
}

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
    /// Exact public origin of this mount for same-origin account listing when
    /// the browser suppresses its referrer. Terminate TLS at a trusted ingress
    /// that enforces this origin and preserves the original request authority.
    pub browser_public_origin: Option<String>,

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
    /// Issue browser memberships for new credential-entry flows.
    pub multi_account: bool,
    /// Opt-in native OAuth 2.1 / OIDC authorization server
    /// (internal/oauth-as.md). Unset means no `/oauth2/*` routes, no signing
    /// key ever generated, and no behavior change.
    ///
    /// **Central only.** An authorization server has exactly one issuer
    /// identity, so `RemoteProvider` ignores this field with a warning rather
    /// than proxying it: a service answering `/oauth2/token` on its own
    /// origin would be minting tokens under central's `iss`, and the
    /// client-side issuer check would fail in ways that look like clock skew.
    #[cfg(feature = "oauth-as")]
    pub oauth_as: Option<super::OauthAsConfig>,
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
    browser_public_origin: Option<String>,
    rate_limiter: Arc<dyn RateLimiter>,
    return_origins: Vec<String>,
    registration: RegistrationMode,
    factor_policy: FactorPolicy,
    multi_account: bool,
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
    let state = Arc::new(EmbeddedState {
        auth_ui_origin: config.auth_ui_origin.clone(),
        session_cors_origins: config.session_cors_origins,
        browser_public_origin: config.browser_public_origin,
        cookie_domain: config.cookie_domain,
        session_ttl: config.session_ttl,
        rate_limiter: config.rate_limiter.expect("embedded mode requires rate_limiter"),
        return_origins: config.return_origins.unwrap_or_default(),
        registration: config.registration.unwrap_or(RegistrationMode::Closed),
        factor_policy: config.factor_policy.unwrap_or(FactorPolicy::None),
        multi_account: config.multi_account,
        allow_inline: config.allow_inline.unwrap_or(false),
        engine,
        provider: Arc::clone(&provider),
    });
    let v1 = V1Router::new(Arc::clone(&state)).into_router();

    // The AS mounts two halves: its own browser API under `/v1`, and the
    // OAuth wire protocol at the origin root (see `router::oauth_as`).
    #[cfg(feature = "oauth-as")]
    let (v1, oauth_as_root) = if let Some(as_config) = config.oauth_as.as_ref() {
        let as_state = Arc::new(super::oauth_as::AsState {
            engine: Arc::clone(&state.engine),
            provider: Arc::clone(&provider),
            rate_limiter: Arc::clone(&state.rate_limiter),
            config: as_config.clone(),
            multi_account: state.multi_account,
            cookie_domain: state.cookie_domain.clone(),
            cimd: super::oauth_as::cimd_resolver(as_config),
        });
        let session_cors = if state.session_cors_origins.is_empty() {
            cors::narrow(&state.auth_ui_origin)
        } else {
            cors::union(&state.session_cors_origins)
        };
        (
            v1.merge(super::oauth_as::v1_router(Arc::clone(&as_state), session_cors)),
            super::oauth_as::root_router(as_state),
        )
    } else {
        (v1, Router::new())
    };

    // Outside both CORS zones: it resolves who the caller is on behalf of
    // before any handler reads a rate-limit key.
    let v1 = v1.layer(middleware::from_fn_with_state(
        Arc::new(TrustedProxyState::new(Arc::clone(&state.engine))),
        trusted_proxy,
    )).layer(middleware::map_response(super::no_store));

    let interval = config
        .maintenance_interval
        .unwrap_or(DEFAULT_MAINTENANCE_INTERVAL);
    if !interval.is_zero() {
        spawn_maintenance(Arc::clone(&provider), interval);

        // Key rotation, code/flow expiry and the dynamic-client sweep ride
        // the same cadence, and start for the same reason: a mounted AS with
        // no sweep never rotates a signing key and accumulates dead rows
        // forever.
        #[cfg(feature = "oauth-as")]
        if let Some(as_config) = config.oauth_as.as_ref() {
            super::oauth_as::spawn_oauth_maintenance(
                Arc::clone(&state.engine),
                as_config.clone(),
                interval,
            );
        }
    }

    #[cfg(feature = "oauth-as")]
    let router = Router::new().nest("/v1", v1).merge(oauth_as_root);
    #[cfg(not(feature = "oauth-as"))]
    let router = Router::new().nest("/v1", v1);
    router
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
        let accounts = Router::new()
            .route("/accounts", get(list_accounts).options(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn_with_state(Arc::clone(&self.state), authorize_account_list))
            .with_state(Arc::clone(&self.state));
        let session_management = Router::new()
            .route("/whoami", get(whoami))
            .route("/accounts/default", axum::routing::put(set_default_account).layer(csrf()))
            .route("/accounts/{account_id}", delete(remove_browser_account).layer(csrf()))
            .route("/logout-all", post(logout_all).layer(csrf()))
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
            .layer(cors::account_scoped(session_cors))
            .with_state(self.state);

        Router::new()
            .merge(credential_entry)
            .merge(accounts)
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
pub(crate) struct MaybeClientIp(pub(crate) Option<std::net::IpAddr>);

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
    intent: Option<LoginIntent>,
    return_to: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum LoginIntent {
    AddAccount,
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

            let origin = return_url.origin().ascii_serialization();
            let allowed = matches!(return_url.scheme(), "https" | "http")
                && (origin == state.auth_ui_origin || state.return_origins.contains(&origin));

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

    let token = browser_cookie(&headers)?;
    let flow = if state.multi_account {
        state.engine
            .create_browser_login_flow(return_to, query.intent.is_some(), token.as_ref(), legacy_cookie(&headers).as_ref())
            .await?
    } else {
        if query.intent.is_some() || token.is_some() {
            return Err(AuthError::Forbidden.into());
        }
        state.engine.create_login_flow(return_to).await?
    };

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
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let flow = state.engine
        .get_browser_login_flow(&id, browser_cookie(&headers)?.as_ref(), legacy_cookie(&headers).as_ref())
        .await?;

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
    headers: HeaderMap,
    Json(body): Json<PasswordSubmit>,
) -> Result<Response, ApiError> {
    let flow = state.engine
        .get_browser_login_flow(&id, browser_cookie(&headers)?.as_ref(), legacy_cookie(&headers).as_ref())
        .await?;

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
    let (identity, proof) = match state.engine.verify_login_password(&username, &password).await {
        Ok(identity) => identity,
        Err(e) => {
            state.engine.record_flow_error(&id, "invalid_credentials").await?;
            return Err(e.into());
        }
    };

    if state.engine.has_totp(identity.id).await? {
        state
            .engine
            .set_flow_awaiting_totp(&id, proof)
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
        &body.csrf_token,
        &headers,
        flow.return_to,
        VerifiedLogin::Password(proof),
        "authenticate",
        Some(json!({ "factors": ["password"] })),
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
    csrf: &str,
    headers: &HeaderMap,
    return_to: Option<String>,
    verified: VerifiedLogin,
    audit_action: &str,
    audit_detail: Option<serde_json::Value>,
) -> Result<Response, ApiError> {
    let completed = state
        .engine
        .finish_login_flow(
            flow_id,
            csrf,
            browser_cookie(headers)?.as_ref(),
            legacy_cookie(headers).as_ref(),
            state.multi_account,
            verified,
            audit_action,
            audit_detail,
        )
        .await?;
    let issued = completed.issued;
    let mut jar = CookieJar::new();
    if completed.adopted_legacy {
        jar = jar.add(removal_cookie(&state.cookie_domain));
    }
    if let Some(browser) = completed.browser_cookie {
        let mut cookie = session_cookie(
            browser.token.expose_secret(),
            &state.cookie_domain,
            (browser.expires_at - chrono::Utc::now()).num_seconds(),
        );
        cookie.set_name(crate::extract::BROWSER_COOKIE);
        jar = jar.add(cookie);
    } else if completed.account_id.is_none() {
        jar = jar.add(session_cookie(
            issued.token.expose_secret(),
            &state.cookie_domain,
            state.session_ttl.as_secs() as i64,
        ));
    }
    let policy = policy_from_status(state.factor_policy, completed.factor_status);
    let mut body = json!({ "return_to": return_to, "session": issued.session, "policy": policy });
    if let Some(account) = completed.account_id {
        let callback = body["return_to"].as_str()
            .and_then(|value| url::Url::parse(value).ok())
            .filter(|url| url.fragment() == Some("surge_account"));
        if let Some(mut url) = callback {
            // Check after credential verification and membership attachment.
            // A registry error withholds the selector while still delivering
            // the cookie for the completed login.
            let origin = url.origin().ascii_serialization();
            let allowed = account_list_origin_allowed(state, &origin).await.unwrap_or_else(|error| {
                tracing::warn!(%error, "could not authorize login callback account selector");
                false
            });
            if allowed {
                url.set_fragment(Some(&format!("surge_account={account}")));
                body["return_to"] = json!(url.as_str());
                body["account_id"] = json!(account);
            }
        } else {
            body["account_id"] = json!(account);
        }
    }
    Ok((jar, Json(body)).into_response())
}

/// The soft-policy compliance block surfaced to the frontend.
async fn policy_block(
    state: &EmbeddedState,
    identity_id: IdentityId,
) -> Result<serde_json::Value, AuthError> {
    let status = state.engine.factor_status(identity_id).await?;
    Ok(policy_from_status(state.factor_policy, status))
}

fn policy_from_status(policy: FactorPolicy, status: surge_engine::FactorStatus) -> serde_json::Value {
    let (totp_required, passphrase_required) = policy.requires();
    let compliant =
        (!totp_required || status.has_totp) && (!passphrase_required || status.has_passphrase);

    json!({
        "required": { "totp": totp_required, "passphrase": passphrase_required },
        "has": { "totp": status.has_totp, "passphrase": status.has_passphrase },
        "compliant": compliant,
    })
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
    headers: HeaderMap,
    Json(body): Json<TotpSubmit>,
) -> Result<Response, ApiError> {
    let flow = state.engine
        .get_browser_login_flow(&id, browser_cookie(&headers)?.as_ref(), legacy_cookie(&headers).as_ref())
        .await?;
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

    let result = finish_login(
        &state,
        &id,
        &body.csrf_token,
        &headers,
        flow.return_to,
        VerifiedLogin::Totp(identity_id, body.code),
        "authenticate",
        Some(json!({ "factors": ["password", "totp"] })),
    )
    .await;
    if matches!(result, Err(ApiError(AuthError::InvalidCredentials))) {
        state.engine.record_flow_error(&id, "invalid_totp").await?;
    }
    result
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
    headers: HeaderMap,
    Json(body): Json<PassphraseLogin>,
) -> Result<Response, ApiError> {
    let flow = state.engine
        .get_browser_login_flow(&id, browser_cookie(&headers)?.as_ref(), legacy_cookie(&headers).as_ref())
        .await?;
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
        .verify_login_passphrase(&username, &body.passphrase)
        .await
    {
        Ok((_, proof)) => {
            finish_login(
                &state,
                &id,
                &body.csrf_token,
                &headers,
                flow.return_to,
                VerifiedLogin::Passphrase(proof),
                "passphrase_login",
                Some(json!({ "factors": ["passphrase"] })),
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
    headers: HeaderMap,
    Json(body): Json<RecoverSubmit>,
) -> Result<Response, ApiError> {
    let flow = state.engine
        .get_browser_login_flow(&id, browser_cookie(&headers)?.as_ref(), legacy_cookie(&headers).as_ref())
        .await?;
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
        .verify_login_passphrase(&username, &body.passphrase)
        .await
    {
        Ok((_, proof)) => {
            finish_login(
                &state,
                &id,
                &body.csrf_token,
                &headers,
                flow.return_to,
                VerifiedLogin::Recover(proof, new_password),
                "password_reset",
                Some(json!({ "factors": ["passphrase"] })),
            )
            .await
        }
        Err(e) => {
            state.engine.record_flow_error(&id, "invalid_credentials").await?;
            Err(e.into())
        }
    }
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

impl FromRequestParts<Arc<EmbeddedState>> for ResolvedSession {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<EmbeddedState>) -> Result<Self, Self::Rejection> {
        Ok(resolve_request_parts(&state.provider, parts, false).await?)
    }
}

async fn get_factors(
    State(state): State<Arc<EmbeddedState>>,
    resolved: ResolvedSession,
) -> Result<Response, ApiError> {
    let session = resolved.session;
    let policy = policy_block(&state, session.identity.id).await?;
    Ok(Json(json!({ "policy": policy })).into_response())
}

async fn enroll_totp(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    resolved: ResolvedSession,
    Json(body): Json<StepUp>,
) -> Result<Response, ApiError> {
    let session = resolved.session;
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
    resolved: ResolvedSession,
    Json(body): Json<ConfirmTotp>,
) -> Result<Response, ApiError> {
    let session = resolved.session;
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
    resolved: ResolvedSession,
    Json(body): Json<StepUp>,
) -> Result<Response, ApiError> {
    let session = resolved.session;
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
    resolved: ResolvedSession,
    Json(body): Json<StepUp>,
) -> Result<Response, ApiError> {
    let session = resolved.session;
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
    resolved: ResolvedSession,
    Json(body): Json<ConfirmPassphrase>,
) -> Result<Response, ApiError> {
    let session = resolved.session;
    let id = session.identity.id;
    rate_limit_step_up(&state, ip, id).await?;
    state.engine.confirm_passphrase(id, &body.passphrase).await?;
    let policy = policy_block(&state, id).await?;
    Ok(Json(json!({ "policy": policy })).into_response())
}

async fn remove_passphrase(
    State(state): State<Arc<EmbeddedState>>,
    MaybeClientIp(ip): MaybeClientIp,
    resolved: ResolvedSession,
    Json(body): Json<StepUp>,
) -> Result<Response, ApiError> {
    let session = resolved.session;
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
    resolved: ResolvedSession,
    Json(body): Json<ChangePassword>,
) -> Result<Response, ApiError> {
    let session = resolved.session;
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
    headers: HeaderMap,
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

    let flow = state.engine
        .get_browser_login_flow(&id, browser_cookie(&headers)?.as_ref(), legacy_cookie(&headers).as_ref())
        .await?;
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

    let mut response = finish_login(&state, &id, &body.csrf_token, &headers, flow.return_to,
        VerifiedLogin::Register(req), "register_and_authenticate", None).await?;
    *response.status_mut() = StatusCode::CREATED;
    Ok(response)
}

/// Browser->Surge session resolution: the frontend's "am I logged in, and
/// who am I?" call. Read-only, so no CSRF gate — it only inspects the
/// session cookie. Cross-origin callers need `session_cors_origins`
/// (§8.2b); same-origin frontends work with it empty.
async fn whoami(State(state): State<Arc<EmbeddedState>>, resolved: ResolvedSession) -> Result<impl IntoResponse, ApiError> {
    let session = resolved.session;
    let policy = policy_block(&state, session.identity.id).await?;
    let mut body = serde_json::to_value(&session).unwrap();
    body["policy"] = policy;
    let mut response = Json(body).into_response();
    if let Some(id) = resolved.account_id {
        response.headers_mut().insert(ACCOUNT_HEADER, id.to_string().parse().unwrap());
    }
    Ok(response)
}

async fn account_list_origin_allowed(state: &EmbeddedState, origin: &str) -> Result<bool, AuthError> {
    if origin == state.auth_ui_origin {
        return Ok(true);
    }
    state.engine.can_list_accounts(origin).await
}

async fn authorize_account_list(
    State(state): State<Arc<EmbeddedState>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> Result<Response, ApiError> {
    use http::header::*;
    let origin = cors::list_origin(request.headers(), request.uri(), state.browser_public_origin.as_deref()).ok_or(AuthError::Forbidden)?;
    if !account_list_origin_allowed(&state, &origin).await? {
        return Err(AuthError::Forbidden.into());
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin.parse().map_err(|_| AuthError::Forbidden)?);
    headers.insert(ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
    headers.insert(ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET"));
    headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("content-type, x-surge-csrf"));
    headers.append(VARY, HeaderValue::from_static("Origin, Referer, Sec-Fetch-Site"));
    Ok(response)
}

async fn list_accounts(
    State(state): State<Arc<EmbeddedState>>,
    headers: HeaderMap,
) -> Result<Json<surge_engine::BrowserAccountList>, ApiError> {
    let accounts = match browser_cookie(&headers)? {
        Some(token) => state.engine.list_browser_accounts(&token).await?,
        None => Default::default(),
    };
    Ok(Json(accounts))
}

#[derive(Deserialize)]
struct DefaultAccountBody {
    account_id: uuid::Uuid,
}

async fn set_default_account(
    State(state): State<Arc<EmbeddedState>>,
    headers: HeaderMap,
    Json(body): Json<DefaultAccountBody>,
) -> Result<StatusCode, ApiError> {
    let token = browser_cookie(&headers)?.ok_or(AuthError::InvalidToken)?;
    state
        .engine
        .set_default_account(&token, body.account_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_browser_account(
    State(state): State<Arc<EmbeddedState>>,
    headers: HeaderMap,
    Path(account): Path<uuid::Uuid>,
) -> Result<StatusCode, ApiError> {
    let token = browser_cookie(&headers)?.ok_or(AuthError::InvalidToken)?;
    state
        .engine
        .remove_browser_account(&token, account, None)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn logout_all(
    State(state): State<Arc<EmbeddedState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(token) = browser_cookie(&headers)? {
        state.engine.logout_browser(&token).await?;
    } else if let Some(token) = legacy_cookie(&headers) {
        state.engine.logout_legacy_browser(&token).await?;
    }
    let mut browser = removal_cookie(&state.cookie_domain);
    browser.set_name(crate::extract::BROWSER_COOKIE);
    let jar = CookieJar::new()
        .add(browser)
        .add(removal_cookie(&state.cookie_domain));
    Ok((jar, StatusCode::NO_CONTENT).into_response())
}

async fn logout(
    State(state): State<Arc<EmbeddedState>>,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    let (mut parts, _) = request.into_parts();
    if let Some(token) = browser_cookie(&parts.headers)? {
        let resolved = resolve_request_parts(&state.provider, &mut parts, false).await?;
        let account = resolved.account_id.ok_or(AuthError::InvalidToken)?;
        state
            .engine
            .remove_browser_account(&token, account, Some(resolved.session.id))
            .await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    if parts.headers.contains_key(ACCOUNT_HEADER) {
        return Err(AuthError::InvalidToken.into());
    }
    if let Some(token) = legacy_cookie(&parts.headers) {
        state.engine.logout_legacy_browser(&token).await?;
    }
    let jar = CookieJar::new().add(removal_cookie(&state.cookie_domain));
    Ok((jar, StatusCode::NO_CONTENT).into_response())
}
