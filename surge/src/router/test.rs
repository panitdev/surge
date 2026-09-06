//! The `TestProvider` browser perimeter: read-only session introspection.
//!
//! `TestProvider` authenticates every request as one fixed identity, so
//! there is nothing here to mutate — no login flow to start, no session to
//! revoke, no factor to enroll. Only `GET /v1/whoami` is served; every
//! other perimeter route answers 501 the way the `AuthProvider` default
//! does.

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use axum_extra::extract::CookieJar;

use super::{cors, BrowserRouterConfig};
use crate::traits::AuthProvider;
use crate::SessionToken;

/// Builds the read-only test browser router at `/v1`. Embedded-only
/// config fields (rate limiter, registration mode, ...) are ignored:
/// nothing here is rate limited because nothing here is a credential.
pub(crate) fn test_browser_router(
    provider: Arc<dyn AuthProvider>,
    config: BrowserRouterConfig,
) -> Router {
    let session_cors = if config.session_cors_origins.is_empty() {
        cors::narrow(&config.auth_ui_origin)
    } else {
        cors::union(&config.session_cors_origins)
    };

    let v1 = Router::new()
        .route("/whoami", get(whoami))
        .layer(session_cors)
        .with_state(provider)
        .fallback(|| async {
            (
                axum::http::StatusCode::NOT_IMPLEMENTED,
                Json(serde_json::json!({
                    "error": "not_implemented",
                    "message": "TestProvider serves read-only session \
                                introspection; this route mutates state",
                })),
            )
        });

    Router::new().nest("/v1", v1)
}

/// Always authenticates — that is the whole point of `TestProvider`. The
/// cookie is still read and passed through so the provider sees the same
/// input it would in embedded mode, but a missing one is not an error.
async fn whoami(
    State(provider): State<Arc<dyn AuthProvider>>,
    jar: CookieJar,
) -> impl IntoResponse {
    let token = jar
        .get("surge_session")
        .and_then(|c| SessionToken::from_raw(c.value()));

    match provider.verify_session(token).await {
        Ok(session) => Json(serde_json::to_value(&session).unwrap()).into_response(),
        // Unreachable for TestProvider, but the trait permits an error and
        // matching the real perimeter's 401 beats unwrapping.
        Err(_) => (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_token" })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_provider::{TestConfig, TestProvider};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::time::Duration;
    use tower::ServiceExt;

    fn router() -> Router {
        let provider: Arc<dyn AuthProvider> =
            Arc::new(TestProvider::new(TestConfig::default()).unwrap());
        test_browser_router(
            provider,
            BrowserRouterConfig {
                cookie_domain: "localhost".into(),
                session_ttl: Duration::from_secs(3600),
                auth_ui_origin: "http://localhost:5173".into(),
                session_cors_origins: Vec::new(),
                rate_limiter: None,
                return_origins: None,
                registration: None,
                factor_policy: None,
                allow_inline: None,
                oauth_bridge: None,
                #[cfg(feature = "oauth-as")]
                oauth_as: None,
                maintenance_interval: None,
            },
        )
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn whoami_succeeds_without_a_cookie() {
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/whoami")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["identity"]["username"], "test-user");
        assert_eq!(body["identity"]["display_name"], "Test User");
    }

    #[tokio::test]
    async fn mutating_routes_are_not_implemented() {
        let response = router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/logout")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let body = body_json(response).await;
        assert_eq!(body["error"], "not_implemented");
    }
}
