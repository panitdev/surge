use http::header::HeaderName;
use tower_http::cors::{AllowOrigin, CorsLayer};

static CSRF_HEADER: HeaderName = HeaderName::from_static("x-surge-csrf");

fn base() -> CorsLayer {
    CorsLayer::new()
        .allow_credentials(true)
        .allow_methods([http::Method::GET, http::Method::POST])
        .allow_headers([
            http::header::CONTENT_TYPE,
            http::header::COOKIE,
            CSRF_HEADER.clone(),
        ])
}

/// Single-origin CORS zone (credential-entry default; session-management
/// default when `session_cors_origins` is empty).
pub(crate) fn narrow(origin: &str) -> CorsLayer {
    match origin.parse() {
        Ok(value) => base().allow_origin(AllowOrigin::exact(value)),
        Err(_) => base().allow_origin(AllowOrigin::list(Vec::new())),
    }
}

/// Credentialed CORS over the union of registered return origins — the
/// opt-in browser->Surge session-management zone (§8.2b).
pub(crate) fn union(origins: &[String]) -> CorsLayer {
    let parsed = origins.iter().filter_map(|o| o.parse().ok()).collect::<Vec<_>>();
    base().allow_origin(AllowOrigin::list(parsed))
}
