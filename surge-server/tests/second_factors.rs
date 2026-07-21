//! End-to-end tests for the TOTP and passphrase factors: enrollment, the
//! mandatory TOTP step after password, standalone passphrase login, and
//! passphrase-authorized recovery.
//!
//! Real end-to-end tests against a live Postgres, `#[ignore]`d by default so a
//! plain `cargo test` never touches a database. To run:
//!
//!   DATABASE_URL=postgres://localhost/surge_canary_test \
//!     cargo test -p surge-server --test second_factors -- --ignored

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use secrecy::SecretString;
use serde_json::{json, Value};
use totp_rs::{Algorithm, Secret, TOTP};
use tower::ServiceExt;

use surge::router::FactorPolicy;
use surge::{EmbeddedConfig, EmbeddedProvider};
use surge_server::config::ServerConfig;

const AUTH_UI_ORIGIN: &str = "https://auth.factors.test";
const RETURN_ORIGIN: &str = "https://app.factors.test";
const PASSWORD: &str = "correct horse battery staple";

async fn test_app(policy: FactorPolicy) -> (axum::Router, String) {
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set to run this test");

    let embedded = EmbeddedProvider::new(EmbeddedConfig {
        database_url: SecretString::from(database_url),
        pepper: SecretString::from("factors-test-pepper".to_string()),
        session_ttl: Duration::from_secs(3600),
    })
    .await
    .expect("failed to stand up EmbeddedProvider against DATABASE_URL");

    let engine = embedded.engine();
    let provider: Arc<dyn surge::AuthProvider> = Arc::new(embedded);

    let svc_name = format!("factors-svc-{}", rand_suffix());
    let token = surge_engine::types::ServiceToken::generate();
    engine
        .create_service(
            &svc_name,
            token.hash(),
            vec!["direct_auth".to_string()],
            vec![RETURN_ORIGIN.to_string()],
        )
        .await
        .expect("create_service");

    let config = Arc::new(ServerConfig {
        database_url: SecretString::from(String::new()),
        pepper: SecretString::from(String::new()),
        bind_addr: String::new(),
        cookie_domain: "factors.test".to_string(),
        auth_ui_origin: AUTH_UI_ORIGIN.to_string(),
        session_ttl_hours: 1,
        registration: surge::router::RegistrationMode::Open,
        factor_policy: policy,
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

async fn body_json(resp: Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// Extract the `surge_session=...` pair from a response's Set-Cookie headers.
fn session_cookie(resp: &Response<Body>) -> Option<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            let pair = c.split(';').next()?;
            if pair.starts_with("surge_session=") && !pair.ends_with('=') {
                Some(pair.to_string())
            } else {
                None
            }
        })
}

async fn register(app: &axum::Router, token: &str, username: &str) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/register")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "username": username, "password": PASSWORD, "display_name": username })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "register setup failed");
}

/// Start an inline flow and return `(flow_id, csrf_token)`.
async fn start_flow(app: &axum::Router) -> (String, String) {
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
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    (
        body["flow_id"].as_str().unwrap().to_string(),
        body["csrf_token"].as_str().unwrap().to_string(),
    )
}

async fn post_flow(app: &axum::Router, flow_id: &str, step: &str, body: Value) -> Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/flows/{flow_id}/{step}"))
                .header("content-type", "application/json")
                .header("origin", AUTH_UI_ORIGIN)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn post_authed(app: &axum::Router, uri: &str, cookie: &str, body: Value) -> Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("origin", AUTH_UI_ORIGIN)
                .header("cookie", cookie)
                .header("x-surge-csrf", "1")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn totp_from_secret(secret_b32: &str) -> TOTP {
    let bytes = Secret::Encoded(secret_b32.to_string()).to_bytes().unwrap();
    TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, bytes, None, "test".into())
}

/// Code for `now + step_offset` windows — used to avoid the replay guard when
/// two codes are needed inside one 30s window (offset the second to +1 step).
fn code_at_offset(totp: &TOTP, step_offset: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let step = (now / 30 + step_offset) as u64;
    totp.generate(step * 30)
}

#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn totp_is_required_after_password_once_enrolled() {
    let (app, token) = test_app(FactorPolicy::Totp).await;
    let username = format!("totp-{}", rand_suffix());
    register(&app, &token, &username).await;

    // Log in with the password to get a session for enrollment.
    let (flow, csrf) = start_flow(&app).await;
    let resp = post_flow(
        &app,
        &flow,
        "password",
        json!({ "username": username, "password": PASSWORD, "csrf_token": csrf }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = session_cookie(&resp).expect("session cookie after password login (no TOTP yet)");
    let body = body_json(resp).await;
    assert_eq!(body["policy"]["compliant"], json!(false), "TOTP required but absent");

    // Enroll TOTP (step-up falls back to the password: no passphrase yet).
    let resp = post_authed(
        &app,
        "/v1/factors/totp/enroll",
        &cookie,
        json!({ "step_up": PASSWORD }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let secret = body_json(resp).await["secret"].as_str().unwrap().to_string();
    let totp = totp_from_secret(&secret);

    let resp = post_authed(
        &app,
        "/v1/factors/totp/confirm",
        &cookie,
        json!({ "code": code_at_offset(&totp, 0) }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "TOTP confirm failed");
    assert_eq!(body_json(resp).await["policy"]["compliant"], json!(true));

    // Re-enrolling while a confirmed TOTP exists must be refused — otherwise it
    // would silently drop the gate and clobber the working secret.
    let resp = post_authed(
        &app,
        "/v1/factors/totp/enroll",
        &cookie,
        json!({ "step_up": PASSWORD }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "re-enroll over a confirmed TOTP must be refused"
    );

    // Fresh login: password now yields totp_required with NO cookie.
    let (flow, csrf) = start_flow(&app).await;
    let resp = post_flow(
        &app,
        &flow,
        "password",
        json!({ "username": username, "password": PASSWORD, "csrf_token": csrf }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(session_cookie(&resp).is_none(), "no session before the TOTP step");
    assert_eq!(body_json(resp).await["status"], json!("totp_required"));

    // Complete with a code for the next step (the confirm consumed this one).
    let resp = post_flow(
        &app,
        &flow,
        "totp",
        json!({ "code": code_at_offset(&totp, 1), "csrf_token": csrf }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "TOTP login step failed");
    assert!(session_cookie(&resp).is_some(), "session issued after TOTP");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn passphrase_logs_in_standalone_and_authorizes_recovery() {
    let (app, token) = test_app(FactorPolicy::None).await;
    let username = format!("pass-{}", rand_suffix());
    register(&app, &token, &username).await;

    // Log in, then set a passphrase (step-up = password, none exists yet).
    let (flow, csrf) = start_flow(&app).await;
    let resp = post_flow(
        &app,
        &flow,
        "password",
        json!({ "username": username, "password": PASSWORD, "csrf_token": csrf }),
    )
    .await;
    let cookie = session_cookie(&resp).unwrap();

    let resp = post_authed(
        &app,
        "/v1/factors/passphrase",
        &cookie,
        json!({ "step_up": PASSWORD }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let passphrase = body_json(resp).await["passphrase"].as_str().unwrap().to_string();
    assert_eq!(passphrase.split(' ').count(), 6, "6-word Diceware passphrase");

    // Standalone passphrase login bypasses the password.
    let (flow, csrf) = start_flow(&app).await;
    let resp = post_flow(
        &app,
        &flow,
        "passphrase",
        json!({ "username": username, "passphrase": passphrase, "csrf_token": csrf }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "passphrase login failed");
    assert!(session_cookie(&resp).is_some());

    // Recovery: passphrase authorizes setting a new password.
    let new_password = "an-entirely-different-secret";
    let (flow, csrf) = start_flow(&app).await;
    let resp = post_flow(
        &app,
        &flow,
        "recover",
        json!({
            "username": username,
            "passphrase": passphrase,
            "new_password": new_password,
            "csrf_token": csrf,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "recovery failed");

    // The new password now works.
    let (flow, csrf) = start_flow(&app).await;
    let resp = post_flow(
        &app,
        &flow,
        "password",
        json!({ "username": username, "password": new_password, "csrf_token": csrf }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "login with the reset password failed");
    assert!(session_cookie(&resp).is_some());
}
