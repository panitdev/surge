pub mod error;
pub mod middleware;
pub mod service_v1;
pub mod service_v2;

use std::sync::Arc;
use std::time::Duration;

use axum::{Router, http::StatusCode, routing::get};
use surge::router::{browser, BrowserRouterConfig, PostgresRateLimiter, RateLimitConfig};
use surge::AuthProvider;
use surge_engine::Engine;
use tower_http::trace::TraceLayer;
use tracing::warn;

use crate::config::ServerConfig;

pub struct AppState {
    pub engine: Arc<Engine>,
    pub provider: Arc<dyn AuthProvider>,
}

/// Central startup coherence (architecture.md §5): refuse to start, or
/// warn unmissably, before any request can hit a config gap that would
/// otherwise only surface at the worst possible time — a real login unable
/// to redirect back, or credentialed CORS silently rejecting the auth UI
/// itself.
fn check_startup_coherence(config: &ServerConfig, return_origins: &[String]) -> anyhow::Result<()> {
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

    if let Some(bridge) = &config.hydra_bridge {
        if !return_origins.iter().any(|o| o == &bridge.bridge_origin) {
            anyhow::bail!(
                "SURGE_HYDRA_ADMIN_URL is set but SURGE_HYDRA_BRIDGE_ORIGIN ({}) is not among \
                 registered return_origins; the bridge's own return_to callback would be \
                 rejected by GET /v1/login's origin check, silently breaking every login \
                 challenge. Register it with `surge-server svc create --origin`.",
                bridge.bridge_origin
            );
        }
    }

    Ok(())
}

/// Assembles the introspection router (service-facing, this crate's own,
/// versioned per architecture.md §4) and mounts the facade's browser
/// router underneath it — the same mountable perimeter any embedded
/// service would use, standalone-hosted here on `auth_ui_origin`.
pub async fn router(
    engine: Arc<Engine>,
    provider: Arc<dyn AuthProvider>,
    config: Arc<ServerConfig>,
) -> anyhow::Result<Router> {
    let state = Arc::new(AppState {
        engine: Arc::clone(&engine),
        provider: Arc::clone(&provider),
    });

    let return_origins = engine.all_return_origins().await?;
    check_startup_coherence(&config, &return_origins)?;

    let rate_limiter = Arc::new(PostgresRateLimiter::new(
        Arc::clone(&engine),
        RateLimitConfig::default(),
    ));

    let oauth_bridge = config.hydra_bridge.as_ref().map(|bridge| {
        surge::router::OauthBridgeConfig {
            hydra_admin_url: bridge.admin_url.clone(),
            hydra_admin_timeout: bridge.admin_timeout,
            bridge_origin: bridge.bridge_origin.clone(),
        }
    });

    let browser_router = browser(BrowserRouterConfig {
        engine: Arc::clone(&engine),
        provider: Arc::clone(&provider),
        rate_limiter,
        cookie_domain: config.cookie_domain.clone(),
        session_ttl: config.session_ttl(),
        auth_ui_origin: config.auth_ui_origin.clone(),
        session_cors_origins: config.session_cors_origins.clone(),
        return_origins,
        registration: config.registration,
        allow_inline: config.allow_served_inline,
        oauth_bridge,
    });

    browser_router.spawn_maintenance(Duration::from_secs(15 * 60));

    Ok(Router::new()
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .nest("/v1", service_v1::router(Arc::clone(&state)))
        .nest("/v2", service_v2::router(state))
        .merge(browser_router.into_axum())
        .layer(TraceLayer::new_for_http()))
}
