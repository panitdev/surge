pub mod error;
pub mod middleware;
pub mod service;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use surge::router::{browser, BrowserRouterConfig, PostgresRateLimiter, RateLimitConfig};
use surge::AuthProvider;
use surge_engine::Engine;
use tower_http::trace::TraceLayer;

use crate::config::ServerConfig;

pub struct AppState {
    pub engine: Arc<Engine>,
    pub provider: Arc<dyn AuthProvider>,
}

/// Assembles the introspection router (service-facing, this crate's own)
/// and mounts the facade's browser router underneath it — the same
/// mountable perimeter any embedded service would use, standalone-hosted
/// here on `auth_ui_origin`.
pub async fn router(
    engine: Arc<Engine>,
    provider: Arc<dyn AuthProvider>,
    config: Arc<ServerConfig>,
) -> anyhow::Result<Router> {
    let state = Arc::new(AppState {
        engine: Arc::clone(&engine),
        provider: Arc::clone(&provider),
    });

    let service_router = service::router(Arc::clone(&state));

    let return_origins = engine.all_return_origins().await?;
    let rate_limiter = Arc::new(PostgresRateLimiter::new(
        Arc::clone(&engine),
        RateLimitConfig::default(),
    ));

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
    });

    browser_router.spawn_maintenance(Duration::from_secs(15 * 60));

    Ok(Router::new()
        .merge(service_router)
        .nest("/v1", browser_router.into_axum())
        .layer(TraceLayer::new_for_http()))
}
