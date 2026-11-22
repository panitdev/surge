pub mod error;
pub mod middleware;
pub mod service_v1;

use std::sync::Arc;

use axum::{Router, http::StatusCode, routing::get};
use surge::router::{BrowserRouterConfig, PostgresRateLimiter, RateLimitConfig};
use surge::{AuthProvider, EmbeddedProvider};
use tower_http::trace::TraceLayer;
use tracing::warn;

use crate::config::ServerConfig;

pub struct AppState {
    pub engine: Arc<surge_engine::Engine>,
    pub provider: Arc<dyn AuthProvider>,
}

/// Central startup coherence (architecture.md §5): refuse to start, or
/// warn unmissably, before any request can hit a config gap that would
/// otherwise only surface at the worst possible time — a real login unable
/// to redirect back, or credentialed CORS silently rejecting the auth UI
/// itself.
fn check_startup_coherence(
    config: &ServerConfig,
    return_origins: &[String],
    engine_resource_count: i64,
) -> anyhow::Result<()> {
    if return_origins.is_empty() {
        warn!(
            "no redirect-mode consumer return_origins are registered (see `surge-server svc create --origin`); \
             every GET /login redirect will fail return_to validation until one is"
        );
    }

    if !config.session_cors_origins.is_empty()
        && !config
            .session_cors_origins
            .iter()
            .any(|o| o == &config.auth_ui_origin)
    {
        anyhow::bail!(
            "SURGE_SESSION_CORS_ORIGINS is set but does not include auth_ui_origin ({}); \
             the auth UI would be excluded from the credentialed session-management zone it needs",
            config.auth_ui_origin
        );
    }

    if config.allow_served_inline {
        warn!(
            "SURGE_ALLOW_SERVED_INLINE=1: served+inline is acknowledged (architecture.md §6). \
             Credential entry is proxied through the consuming service's origin — central sees \
             that service's IP, not the browser's. Thread a trusted X-Forwarded-For into the \
             rate limiter, or accept coarsened per-client limiting. Password transit through the \
             service origin is incremental risk, not categorical: every service already holds \
             surge_service_token and can mint or introspect sessions."
        );
    }

    if let Some(oauth) = &config.oauth_as {
        // The authorize handler bounces through `GET /v1/login?return_to=<self>`,
        // which validates the issuer against the registered return origins.
        if !return_origins.iter().any(|o| o == &oauth.issuer) {
            anyhow::bail!(
                "SURGE_OAUTH_ISSUER ({}) is not among registered return_origins; the \
                 authorization endpoint re-enters GET /v1/login with a return_to pointing at \
                 itself, which would be rejected, silently breaking every authorization. \
                 Register it with `surge-server svc create --origin`.",
                oauth.issuer
            );
        }

        if engine_resource_count == 0 {
            warn!(
                "the OAuth authorization server is enabled but no resources are registered; \
                 every authorize request will fail resource validation until one is (see \
                 `surge-server oauth resource create`)"
            );
        }

        if config.allow_dynamic_registration_warning() {
            warn!(
                "SURGE_OAUTH_ALLOW_DYNAMIC_REGISTRATION=1: /oauth2/register is open and \
                 unauthenticated by specification. It is rate-limited per IP and its clients are \
                 always untrusted, third-party, and consent-gated — but this is the largest \
                 abuse surface the server exposes."
            );
        }
    }

    Ok(())
}

/// Assembles the introspection router (service-facing, this crate's own,
/// versioned per architecture.md §4) and mounts the provider's browser
/// router underneath it.
pub async fn router(
    embedded: Arc<EmbeddedProvider>,
    config: Arc<ServerConfig>,
) -> anyhow::Result<Router> {
    let engine = embedded.engine();
    let provider: Arc<dyn AuthProvider> = Arc::clone(&embedded) as _;

    let state = Arc::new(AppState {
        engine: Arc::clone(&engine),
        provider: Arc::clone(&provider),
    });

    let return_origins = engine.all_return_origins().await?;
    let oauth_resource_count = if config.oauth_as.is_some() {
        engine.count_oauth_resources().await?
    } else {
        0
    };
    check_startup_coherence(&config, &return_origins, oauth_resource_count)?;

    let rate_limiter = Arc::new(PostgresRateLimiter::new(
        Arc::clone(&engine),
        RateLimitConfig::default(),
    ));

    let oauth_as = config.oauth_as.as_ref().map(|oauth| surge::router::OauthAsConfig {
        issuer: oauth.issuer.clone(),
        auth_ui_origin: config.auth_ui_origin.clone(),
        access_ttl: oauth.access_ttl,
        refresh_ttl: oauth.refresh_ttl,
        key_rotation: oauth.key_rotation,
        allow_dynamic_registration: oauth.allow_dynamic_registration,
        require_resource: oauth.require_resource,
        default_resource: oauth.default_resource.clone(),
        dcr_ttl: oauth.dcr_ttl,
        enable_oidc: oauth.enable_oidc,
    });

    let browser_router = Arc::clone(&embedded).browser_router(BrowserRouterConfig {
        cookie_domain: config.cookie_domain.clone(),
        session_ttl: config.session_ttl(),
        auth_ui_origin: config.auth_ui_origin.clone(),
        session_cors_origins: config.session_cors_origins.clone(),
        rate_limiter: Some(rate_limiter),
        return_origins: Some(return_origins),
        registration: Some(config.registration),
        factor_policy: Some(config.factor_policy),
        allow_inline: Some(config.allow_served_inline),
        multi_account: config.multi_account,
        oauth_as,
        // Mounting the router starts the sweep.
        maintenance_interval: None,
    });

    Ok(Router::new()
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .nest("/v1", service_v1::router(state))
        .merge(browser_router)
        .layer(TraceLayer::new_for_http()))
}
