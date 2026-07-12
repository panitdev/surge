//! `GET /login`'s `return_to` is required for browser-navigation
//! (non-inline) logins but optional in inline mode (`allow_inline` +
//! `Accept: application/json`) — an embedded caller on that path manages
//! its own post-login navigation. See rfc discussion in
//! `surge/src/router/browser.rs`'s `start_login`.
//!
//! These are real end-to-end tests against a live Postgres and are
//! `#[ignore]`d by default so a plain `cargo test` never touches a
//! database. To run them, point `DATABASE_URL` at a disposable Postgres
//! (never a shared/production instance) and run:
//!
//!   DATABASE_URL=postgres://localhost/surge_canary_test \
//!     cargo test -p surge-server --test login_return_to_optional -- --ignored

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use secrecy::SecretString;
use serde_json::{json, Value};
use tower::ServiceExt;

use surge::{EmbeddedConfig, EmbeddedProvider};
use surge_server::config::ServerConfig;

const AUTH_UI_ORIGIN: &str = "https://auth.canary.test";
const RETURN_ORIGIN: &str = "https://app.canary.test";

async fn test_app() -> (axum::Router, String) {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run this test");

    let embedded = EmbeddedProvider::new(EmbeddedConfig {
        database_url: SecretString::from(database_url),
        pepper: SecretString::from("return-to-test-pepper".to_string()),
        session_ttl: Duration::from_secs(3600),
    })
    .await
    .expect("failed to stand up EmbeddedProvider against DATABASE_URL");

    let engine = embedded.engine();
    let provider: Arc<dyn surge::AuthProvider> = Arc::new(embedded);

    let suffix: u32 = rand_suffix();
    let svc_name = format!("return-to-svc-{suffix}");
    let token = surge_engine::types::ServiceToken::generate();
    engine
        .create_service(
            &svc_name,
            token.hash(),
            vec![
                "direct_auth".to_string(),
                "introspect".to_string(),
                "revoke".to_string(),
            ],
            vec![RETURN_ORIGIN.to_string()],
        )
        .await
        .expect("create_service");

    let config = Arc::new(ServerConfig {
        database_url: SecretString::from(String::new()),
        pepper: SecretString::from(String::new()),
        bind_addr: String::new(),
        cookie_domain: "canary.test".to_string(),
        auth_ui_origin: AUTH_UI_ORIGIN.to_string(),
        session_ttl_hours: 1,
        registration: surge::router::RegistrationMode::Open,
        session_cors_origins: vec![],
        allow_served_inline: true,
        hydra_bridge: None,
    });

    let app = surge_server::api::router(Arc::clone(&engine), provider, config)
        .await
        .expect("router assembly");

    (app, token.expose_secret().to_string())
}

fn rand_suffix() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos()) ^ std::process::id()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn register_identity(app: &axum::Router, token: &str, username: &str) -> String {
    let password = "correct horse battery staple";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/register")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": username,
                        "password": password,
                        "display_name": username,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "register setup failed");
    password.to_string()
}

#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn inline_login_without_return_to_succeeds_and_completes_with_null() {
    let (app, token) = test_app().await;
    let username = format!("noreturn-{}", rand_suffix());
    let password = register_identity(&app, &token, &username).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/login")
                .header("accept", "application/json")
                .header("origin", AUTH_UI_ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "inline start_login without return_to must succeed");
    let body = body_json(resp).await;
    let flow_id = body["flow_id"].as_str().unwrap().to_string();
    let csrf_token = body["csrf_token"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/flows/{flow_id}/password"))
                .header("content-type", "application/json")
                .header("origin", AUTH_UI_ORIGIN)
                .body(Body::from(
                    json!({
                        "username": username,
                        "password": password,
                        "csrf_token": csrf_token,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "submit_password failed");
    let body = body_json(resp).await;
    assert_eq!(body["return_to"], Value::Null, "return_to must be explicit null when omitted");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn non_inline_login_without_return_to_is_rejected() {
    let (app, _token) = test_app().await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/login")
                .header("origin", AUTH_UI_ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "browser-navigation login without return_to must be rejected"
    );
}
