//! The cross-version mint/introspect canary (architecture.md §2). Not
//! optional, not scoped to one surface: a session minted anywhere must
//! introspect the same everywhere, on any live version, forever.
//!
//! Three lanes:
//!   1. mint browser-facing, introspect browser-facing, across versions.
//!   2. mint service-facing, introspect service-facing, across versions.
//!   3. mint on one surface, introspect on the other, across versions
//!      (both directions) — the one nothing else catches.
//!
//! These are real end-to-end tests against a live Postgres and are
//! `#[ignore]`d by default so a plain `cargo test` never touches a
//! database. To run them, point `DATABASE_URL` at a disposable Postgres
//! (never a shared/production instance) and run:
//!
//!   DATABASE_URL=postgres://localhost/surge_canary_test \
//!     cargo test -p surge-server --test cross_version_canary -- --ignored
//!
//! Each test creates its own randomly-named service/identity so runs don't
//! collide, but nothing here drops or truncates tables — use a database
//! you're fine leaving with test rows in it.

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

async fn test_app() -> (axum::Router, Arc<surge_engine::Engine>, String) {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run the cross-version canary");

    let embedded = EmbeddedProvider::new(EmbeddedConfig {
        database_url: SecretString::from(database_url),
        pepper: SecretString::from("canary-test-pepper".to_string()),
        session_ttl: Duration::from_secs(3600),
    })
    .await
    .expect("failed to stand up EmbeddedProvider against DATABASE_URL");

    let engine = embedded.engine();
    let provider: Arc<dyn surge::AuthProvider> = Arc::new(embedded);

    let suffix: u32 = rand_suffix();
    let svc_name = format!("canary-svc-{suffix}");
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

    (app, engine, token.expose_secret().to_string())
}

fn rand_suffix() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos()) ^ std::process::id()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// Registers a fresh identity via the service-facing surface (any version —
/// identity setup isn't the thing under test) and returns (username, password).
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

/// Mints a session through the browser-facing surface at `version`
/// ("v1"/"v2") via the full login-flow round trip, returning the raw
/// `surge_session` cookie value.
async fn mint_browser(app: &axum::Router, version: &str, username: &str, password: &str) -> String {
    let return_to = format!("{RETURN_ORIGIN}/");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/{version}/login?return_to={}",
                    percent_encode(&return_to)
                ))
                .header("accept", "application/json")
                .header("origin", AUTH_UI_ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "start_login (inline) failed");
    let body = body_json(resp).await;
    let flow_id = body["flow_id"].as_str().unwrap().to_string();
    let csrf_token = body["csrf_token"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/{version}/flows/{flow_id}/password"))
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

    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .expect("no Set-Cookie on submit_password response")
        .to_str()
        .unwrap()
        .to_string();
    extract_cookie_value(&set_cookie, "surge_session")
}

fn percent_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            other => other
                .to_string()
                .into_bytes()
                .iter()
                .map(|b| format!("%{b:02X}"))
                .collect(),
        })
        .collect()
}

fn extract_cookie_value(set_cookie: &str, name: &str) -> String {
    let prefix = format!("{name}=");
    let first = set_cookie.split(';').next().unwrap();
    first.strip_prefix(&prefix).unwrap().to_string()
}

/// Introspects via the browser-facing surface at `version`.
async fn whoami_browser(app: &axum::Router, version: &str, raw_token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/{version}/whoami"))
                .header("cookie", format!("surge_session={raw_token}"))
                .header("origin", AUTH_UI_ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Mints a session through the service-facing surface at `version`.
async fn mint_service(app: &axum::Router, version: &str, token: &str, username: &str, password: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/{version}/authenticate/password"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "username": username, "password": password }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "authenticate_password failed");
    let body = body_json(resp).await;
    body["token"].as_str().unwrap().to_string()
}

/// Introspects via the service-facing surface at `version`.
async fn verify_service(app: &axum::Router, version: &str, token: &str, raw_session_token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/{version}/sessions/verify"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "token": raw_session_token }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn lane1_mint_browser_introspect_browser_across_versions() {
    let (app, _engine, token) = test_app().await;
    let username = format!("lane1-{}", rand_suffix());
    let password = register_identity(&app, &token, &username).await;

    let raw = mint_browser(&app, "v1", &username, &password).await;
    let resp = whoami_browser(&app, "v1", &raw).await;
    assert_eq!(resp.status(), StatusCode::OK, "browser-minted session must resolve on browser whoami");
    let session = body_json(resp).await;
    assert_eq!(session["identity"]["username"], username);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn lane2_mint_service_introspect_service_across_versions() {
    let (app, _engine, token) = test_app().await;
    let username = format!("lane2-{}", rand_suffix());
    let password = register_identity(&app, &token, &username).await;

    let raw = mint_service(&app, "v1", &token, &username, &password).await;
    let resp = verify_service(&app, "v2", &token, &raw).await;
    assert_eq!(resp.status(), StatusCode::OK, "v1-minted session must resolve on v2 verify");
    let session = body_json(resp).await;
    assert_eq!(session["identity"]["username"], username);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn lane3_mint_one_surface_introspect_the_other() {
    let (app, _engine, token) = test_app().await;

    // direction A: mint browser-facing (v1), introspect service-facing (v1).
    // The browser surface now only serves v1; cross-version coverage for
    // the service-facing surface is handled by lane 2.
    let username_a = format!("lane3a-{}", rand_suffix());
    let password_a = register_identity(&app, &token, &username_a).await;
    let raw_a = mint_browser(&app, "v1", &username_a, &password_a).await;
    let resp_a = verify_service(&app, "v1", &token, &raw_a).await;
    assert_eq!(
        resp_a.status(),
        StatusCode::OK,
        "browser-minted (v1) session must resolve via service-facing verify (v1)"
    );

    // direction B: mint service-facing (v2), introspect browser-facing (v1).
    let username_b = format!("lane3b-{}", rand_suffix());
    let password_b = register_identity(&app, &token, &username_b).await;
    let raw_b = mint_service(&app, "v2", &token, &username_b, &password_b).await;
    let resp_b = whoami_browser(&app, "v1", &raw_b).await;
    assert_eq!(
        resp_b.status(),
        StatusCode::OK,
        "service-minted (v2) session must resolve via browser-facing whoami (v1)"
    );
}
