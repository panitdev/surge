//! End-to-end tests for the trusted-proxy boundary on the browser
//! perimeter.
//!
//! A `RemoteProvider` reverse-proxies browser traffic here, so every
//! request arrives from the service's address rather than the end user's.
//! The proxy states the real address in `X-Surge-Client-Ip` and proves it
//! may with a `browser_proxy` service token. These tests pin the two
//! halves of that: an unbacked claim is refused, and a backed one is
//! honoured.
//!
//! Real end-to-end tests against a live Postgres, `#[ignore]`d by default so a
//! plain `cargo test` never touches a database. To run:
//!
//!   DATABASE_URL=postgres://localhost/surge_canary_test \
//!     cargo test -p surge-server --test trusted_proxy -- --ignored

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use secrecy::SecretString;
use tower::ServiceExt;

use surge::{EmbeddedConfig, EmbeddedProvider};
use surge_server::config::ServerConfig;

const AUTH_UI_ORIGIN: &str = "https://auth.proxy.test";
const RETURN_ORIGIN: &str = "https://app.proxy.test";

const CLIENT_IP_HEADER: &str = "x-surge-client-ip";
const SERVICE_TOKEN_HEADER: &str = "x-surge-service-token";

struct Tokens {
    /// Carries `browser_proxy`.
    proxy: String,
    /// Valid, but for a service with no `browser_proxy` grant.
    unprivileged: String,
}

async fn test_app() -> (axum::Router, Tokens) {
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set to run this test");

    let embedded = Arc::new(
        EmbeddedProvider::new(EmbeddedConfig {
            database_url: SecretString::from(database_url),
            pepper: SecretString::from("proxy-test-pepper".to_string()),
            session_ttl: Duration::from_secs(3600),
        })
        .await
        .expect("failed to stand up EmbeddedProvider against DATABASE_URL"),
    );

    let engine = embedded.engine();
    let suffix = rand_suffix();

    let proxy = surge_engine::types::ServiceToken::generate();
    engine
        .create_service(
            &format!("proxy-svc-{suffix}"),
            proxy.hash(),
            vec!["browser_proxy".to_string()],
            vec![RETURN_ORIGIN.to_string()],
        )
        .await
        .expect("create_service");

    let unprivileged = surge_engine::types::ServiceToken::generate();
    engine
        .create_service(
            &format!("plain-svc-{suffix}"),
            unprivileged.hash(),
            vec!["introspect".to_string()],
            vec![RETURN_ORIGIN.to_string()],
        )
        .await
        .expect("create_service");

    let config = Arc::new(ServerConfig {
        database_url: SecretString::from(String::new()),
        pepper: SecretString::from(String::new()),
        bind_addr: String::new(),
        cookie_domain: "proxy.test".to_string(),
        auth_ui_origin: AUTH_UI_ORIGIN.to_string(),
        session_ttl_hours: 1,
        registration: surge::router::RegistrationMode::Open,
        factor_policy: surge::router::FactorPolicy::None,
        session_cors_origins: vec![],
        allow_served_inline: true,
        hydra_bridge: None,
        oauth_as: None,
    });

    let app = surge_server::api::router(embedded, config)
        .await
        .expect("router assembly");

    (
        app,
        Tokens {
            proxy: proxy.expose_secret().to_string(),
            unprivileged: unprivileged.expose_secret().to_string(),
        },
    )
}

fn rand_suffix() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos()) ^ std::process::id()
}

/// `GET /v1/login`, optionally claiming to act for another address.
fn login_request(client_ip: Option<&str>, service_token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("/v1/login?return_to={RETURN_ORIGIN}/"))
        .header("accept", "application/json");

    if let Some(ip) = client_ip {
        builder = builder.header(CLIENT_IP_HEADER, ip);
    }
    if let Some(token) = service_token {
        builder = builder.header(SERVICE_TOKEN_HEADER, token);
    }

    builder.body(Body::empty()).unwrap()
}

/// The whole point of the header: without a token backing it, honouring it
/// would let any browser pick its own rate-limit bucket. Refuse rather
/// than silently ignore, so a misconfigured proxy fails loudly instead of
/// quietly rate-limiting all its users as one.
#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn client_ip_claim_without_a_token_is_refused() {
    let (app, _) = test_app().await;

    let resp = app
        .oneshot(login_request(Some("203.0.113.9"), None))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn client_ip_claim_with_an_invalid_token_is_refused() {
    let (app, _) = test_app().await;

    let resp = app
        .oneshot(login_request(
            Some("203.0.113.9"),
            Some("aeg_svc_not_a_real_token"),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A valid token is not enough — `browser_proxy` is the grant that
/// authorizes speaking for someone else.
#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn client_ip_claim_without_the_browser_proxy_grant_is_refused() {
    let (app, tokens) = test_app().await;

    let resp = app
        .oneshot(login_request(
            Some("203.0.113.9"),
            Some(&tokens.unprivileged),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn browser_proxy_token_authorizes_the_claim() {
    let (app, tokens) = test_app().await;

    let resp = app
        .oneshot(login_request(Some("203.0.113.9"), Some(&tokens.proxy)))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

/// Ordinary browser traffic carries neither header and must be untouched
/// by any of this.
#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn unproxied_request_passes_through() {
    let (app, _) = test_app().await;

    let resp = app.oneshot(login_request(None, None)).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

/// The reason the whole mechanism exists. Behind a proxy every request
/// shares one peer address, so a rate limit keyed on it would let one
/// user's failed logins lock out everybody else on that service.
#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn rate_limits_are_keyed_on_the_stated_client_not_the_proxy() {
    // Distinct addresses per run: buckets are keyed on the address
    // literally and persist for the 15-minute window, so a fixed pair
    // would poison later runs against the same database.
    let suffix = rand_suffix() % 250 + 1;
    let noisy = format!("198.51.100.{suffix}");
    let bystander = format!("203.0.113.{suffix}");

    let (app, tokens) = test_app().await;

    // `authenticate` allows 10 per IP per 15 minutes. Each attempt uses a
    // fresh username so only the per-IP bucket accumulates.
    let mut noisy_status = StatusCode::OK;
    for attempt in 0..12 {
        noisy_status = failed_login(
            &app,
            &tokens.proxy,
            &noisy,
            &format!("ghost-{suffix}-{attempt}"),
        )
        .await;
        if noisy_status == StatusCode::TOO_MANY_REQUESTS {
            break;
        }
    }
    assert_eq!(
        noisy_status,
        StatusCode::TOO_MANY_REQUESTS,
        "the noisy client should have exhausted its own budget"
    );

    let bystander_status = failed_login(
        &app,
        &tokens.proxy,
        &bystander,
        &format!("ghost-{suffix}-bystander"),
    )
    .await;
    assert_eq!(
        bystander_status,
        StatusCode::UNAUTHORIZED,
        "a different end user behind the same proxy must still be able to log in"
    );
}

/// One full login attempt against a nonexistent user, on behalf of
/// `client_ip`. Returns the status of the password submission.
async fn failed_login(
    app: &axum::Router,
    proxy_token: &str,
    client_ip: &str,
    username: &str,
) -> StatusCode {
    let resp = app
        .clone()
        .oneshot(login_request(Some(client_ip), Some(proxy_token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let flow: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let flow_id = flow["flow_id"].as_str().unwrap();
    let csrf = flow["csrf_token"].as_str().unwrap();

    let body = serde_json::json!({
        "username": username,
        "password": "definitely not the password",
        "csrf_token": csrf,
    });

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/flows/{flow_id}/password"))
                .header("content-type", "application/json")
                .header(CLIENT_IP_HEADER, client_ip)
                .header(SERVICE_TOKEN_HEADER, proxy_token)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}
