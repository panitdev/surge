//! The cross-version mint/introspect canary (architecture.md §2). Not
//! optional, not scoped to one surface: a session minted anywhere must
//! introspect the same everywhere, on any live version, forever.
//!
//! Three lanes:
//!   1. mint browser-facing, introspect browser-facing.
//!   2. mint service-facing, introspect service-facing.
//!   3. mint on one surface, introspect on the other, both directions —
//!      the one nothing else catches.
//!
//! The version axis is currently dormant: `/v1` is the only mounted
//! surface, so every lane runs v1 -> v1 and what they actually pin is
//! cross-*surface* portability. That is lane 3's real value and it holds
//! regardless. When a second version is mounted, retarget the introspect
//! half of lanes 2 and 3B to it — the lanes are shaped for that and the
//! helpers already take a version argument. Do not delete them in the
//! meantime; a dormant axis is not a retired guarantee.
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
/// The AS issuer, which must also be a registered return origin: the
/// authorize handler bounces through `GET /v1/login?return_to=<self>`.
const OAUTH_ISSUER: &str = "https://canary.test";
const OAUTH_CLIENT_REDIRECT: &str = "https://app.canary.test/oauth/callback";

async fn test_app() -> (axum::Router, Arc<surge_engine::Engine>, String) {
    let (app, engine, token, _resource) = test_app_inner().await;
    (app, engine, token)
}

/// The full harness, including the audience this run registered. Lane 4 needs
/// *its own* resource: the introspection check is scoped to the resources the
/// asking service owns, so picking any row out of a shared database would
/// hand the lane someone else's audience.
async fn test_app_inner() -> (axum::Router, Arc<surge_engine::Engine>, String, String) {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run the cross-version canary");

    let embedded = Arc::new(
        EmbeddedProvider::new(EmbeddedConfig {
            database_url: SecretString::from(database_url),
            // Shared with the OAuth suites on purpose: signing keys are encrypted
            // under the pepper and are per-deployment, so two test binaries
            // pointed at one DATABASE_URL must agree on it.
            pepper: SecretString::from("surge-oauth-test-pepper".to_string()),
            session_ttl: Duration::from_secs(3600),
        })
        .await
        .expect("failed to stand up EmbeddedProvider against DATABASE_URL"),
    );

    let engine = embedded.engine();

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
            vec![RETURN_ORIGIN.to_string(), OAUTH_ISSUER.to_string()],
        )
        .await
        .expect("create_service");

    // Lane 4 needs an audience to scope its token to; the other lanes are
    // indifferent to it.
    let service_id = engine
        .list_services()
        .await
        .unwrap()
        .into_iter()
        .find(|s| s.name == svc_name)
        .unwrap()
        .id;
    let resource_uri = format!("https://rs.canary.test/mcp-{suffix}");
    engine
        .create_oauth_resource(
            &resource_uri,
            service_id,
            vec!["mcp:read".to_string()],
            serde_json::json!({}),
        )
        .await
        .expect("create_oauth_resource");

    let config = Arc::new(ServerConfig {
        database_url: SecretString::from(String::new()),
        pepper: SecretString::from(String::new()),
        bind_addr: String::new(),
        cookie_domain: "canary.test".to_string(),
        auth_ui_origin: AUTH_UI_ORIGIN.to_string(),
        session_ttl_hours: 1,
        registration: surge::router::RegistrationMode::Open,
        factor_policy: surge::router::FactorPolicy::None,
        session_cors_origins: vec![],
        allow_served_inline: true,
        hydra_bridge: None,
        oauth_as: Some(surge_server::config::OauthAsSettings {
            issuer: OAUTH_ISSUER.to_string(),
            access_ttl: Duration::from_secs(600),
            refresh_ttl: Duration::from_secs(30 * 86_400),
            key_rotation: Duration::from_secs(90 * 86_400),
            allow_dynamic_registration: false,
            require_resource: true,
            default_resource: None,
            dcr_ttl: Duration::from_secs(30 * 86_400),
            enable_oidc: true,
        }),
    });

    let app = surge_server::api::router(embedded, config)
        .await
        .expect("router assembly");

    (app, engine, token.expose_secret().to_string(), resource_uri)
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
    let resp = verify_service(&app, "v1", &token, &raw).await;
    assert_eq!(resp.status(), StatusCode::OK, "service-minted session must resolve on service verify");
    let session = body_json(resp).await;
    assert_eq!(session["identity"]["username"], username);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn lane3_mint_one_surface_introspect_the_other() {
    let (app, _engine, token) = test_app().await;

    // direction A: mint browser-facing, introspect service-facing.
    let username_a = format!("lane3a-{}", rand_suffix());
    let password_a = register_identity(&app, &token, &username_a).await;
    let raw_a = mint_browser(&app, "v1", &username_a, &password_a).await;
    let resp_a = verify_service(&app, "v1", &token, &raw_a).await;
    assert_eq!(
        resp_a.status(),
        StatusCode::OK,
        "browser-minted (v1) session must resolve via service-facing verify (v1)"
    );

    // direction B: mint service-facing, introspect browser-facing.
    let username_b = format!("lane3b-{}", rand_suffix());
    let password_b = register_identity(&app, &token, &username_b).await;
    let raw_b = mint_service(&app, "v1", &token, &username_b, &password_b).await;
    let resp_b = whoami_browser(&app, "v1", &raw_b).await;
    assert_eq!(
        resp_b.status(),
        StatusCode::OK,
        "service-minted session must resolve via browser-facing whoami"
    );
}

/// Lane 4: an OAuth access token is a credential in the same substrate as a
/// session, so it has to answer to the same revocation. Mint one through the
/// authorization server, revoke the identity's sessions, and introspection
/// must report `active: false`.
///
/// The grant is bound to the identity rather than to the browser session that
/// authorized it (internal/oauth-as.md §7), so what ends it is the explicit
/// "log this person out everywhere" — not the natural expiry of the session
/// it happened to be born from.
#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn lane4_revoking_every_session_deactivates_the_oauth_grant() {
    let (app, engine, token, resource_uri) = test_app_inner().await;

    let username = format!("lane4-{}", rand_suffix());
    let password = register_identity(&app, &token, &username).await;
    let session = mint_browser(&app, "v1", &username, &password).await;

    let (client, _) = engine
        .create_oauth_client(surge_engine::oauth::NewOauthClient {
            client_name: "Canary client".to_string(),
            client_uri: None,
            logo_uri: None,
            redirect_uris: vec![OAUTH_CLIENT_REDIRECT.to_string()],
            grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
            scopes: vec!["mcp:read".to_string()],
            confidential: false,
            first_party: true,
            registration_source: surge_engine::oauth::RegistrationSource::Admin,
        })
        .await
        .expect("create_oauth_client");

    // A fixed verifier/challenge pair; the PKCE mechanics are covered in
    // `oauth_token.rs`, this lane only needs a token in hand.
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    let authorize = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256&resource={}&scope=mcp:read",
        percent_encode(&client.client_id),
        percent_encode(OAUTH_CLIENT_REDIRECT),
        percent_encode(&resource_uri),
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&authorize)
                .header("cookie", format!("surge_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "authorize must issue a code");
    let redirect = resp
        .headers()
        .get(axum::http::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let code = url::Url::parse(&redirect)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("no code in the redirect");

    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={verifier}",
        percent_encode(&code),
        percent_encode(OAUTH_CLIENT_REDIRECT),
        percent_encode(&client.client_id),
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let token_body = body_json(resp).await;
    assert_eq!(status, StatusCode::OK, "token exchange failed: {token_body}");
    let access = token_body["access_token"].as_str().unwrap().to_string();

    let introspect = |access: String, token: String, app: axum::Router| async move {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(format!("token={}", percent_encode(&access))))
                .unwrap(),
        )
        .await
        .unwrap()
    };

    let body = body_json(introspect(access.clone(), token.clone(), app.clone()).await).await;
    assert_eq!(body["active"], true, "a freshly minted token must introspect live");
    assert_eq!(body["aud"], resource_uri);

    let identity_id = surge_engine::types::IdentityId::from_uuid(
        body["sub"].as_str().unwrap().parse().unwrap(),
    );
    engine.revoke_all_sessions(identity_id).await.unwrap();

    let body = body_json(introspect(access, token, app).await).await;
    assert_eq!(
        body["active"], false,
        "revoking every session must deactivate the OAuth grant it authorized"
    );
}
