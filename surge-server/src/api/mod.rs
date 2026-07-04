pub mod browser;
pub mod error;
pub mod middleware;
pub mod service;

use std::sync::Arc;

use axum::Router;
use surge_engine::Engine;
use tower_http::trace::TraceLayer;

use crate::config::ServerConfig;

pub struct AppState {
    pub engine: Arc<Engine>,
    pub config: Arc<ServerConfig>,
}

pub fn router(engine: Arc<Engine>, config: Arc<ServerConfig>) -> Router {
    let state = Arc::new(AppState {
        engine: Arc::clone(&engine),
        config: Arc::clone(&config),
    });

    let service_router = service::router(Arc::clone(&state));
    let browser_router = browser::router(Arc::clone(&state), &config);

    Router::new()
        .merge(service_router)
        .merge(browser_router)
        .layer(TraceLayer::new_for_http())
}
