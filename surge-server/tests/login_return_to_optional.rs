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

async fn test_app(multi_account: bool) -> (axum::Router, String) {
    let (app, service, _) = test_app_with_engine(multi_account, true).await;
    (app, service)
}

async fn test_app_with_engine(
    multi_account: bool,
    inline: bool,
) -> (axum::Router, String, Arc<surge_engine::Engine>) {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run this test");

    let embedded = Arc::new(
        EmbeddedProvider::new(EmbeddedConfig {
            database_url: SecretString::from(database_url),
            pepper: SecretString::from("return-to-test-pepper".to_string()),
            session_ttl: Duration::from_secs(3600),
        })
        .await
        .expect("failed to stand up EmbeddedProvider against DATABASE_URL"),
    );

    let engine = embedded.engine();

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
        factor_policy: surge::router::FactorPolicy::None,
        browser_public_origin: None,
        session_cors_origins: vec![],
        allow_served_inline: inline,
        multi_account,
        oauth_as: None,
    });

    let app = surge_server::api::router(embedded, config)
        .await
        .expect("router assembly");

    (app, token.expose_secret().to_string(), engine)
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
    let (app, token) = test_app(false).await;
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
    let (app, _token) = test_app(false).await;

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

#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn browser_sign_in_add_and_reauthenticate_preserve_default() {
    let (app, service) = test_app(true).await;
    let mut cookie = String::new();
    let mut accounts = Vec::new();
    let work = format!("work-{}", rand_suffix());
    let personal = format!("personal-{}", rand_suffix());
    for username in [&work, &personal] {
        register_identity(&app, &service, username).await;
    }
    for username in [&work, &personal, &personal] {
        let adding = !cookie.is_empty();
        let uri = if adding { "/v1/login?intent=add_account" } else { "/v1/login" };
        let start = Request::get(uri).header("accept", "application/json")
            .header("cookie", &cookie).body(Body::empty()).unwrap();
        let response = app.clone().oneshot(start).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let flow = body_json(response).await;
        let submit = Request::post(format!("/v1/flows/{}/password", flow["flow_id"].as_str().unwrap()))
            .header("cookie", &cookie).header("origin", AUTH_UI_ORIGIN)
            .header("content-type", "application/json")
            .body(Body::from(json!({"username": username, "password": "correct horse battery staple", "csrf_token": flow["csrf_token"]}).to_string())).unwrap();
        let response = app.clone().oneshot(submit).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        if !adding {
            let header = response.headers()["set-cookie"].to_str().unwrap();
            for attribute in ["surge_browser=", "HttpOnly", "Secure", "SameSite=Lax", "Domain=canary.test", "Path=/"] {
                assert!(header.contains(attribute), "missing {attribute}");
            }
            cookie = header.split(';').next().unwrap().to_owned();
        }
        accounts.push(body_json(response).await["account_id"].as_str().unwrap().to_owned());
    }
    assert_ne!(accounts[0], accounts[1]);
    assert_eq!(accounts[1], accounts[2]);
    let whoami = Request::get("/v1/whoami").header("cookie", cookie).body(Body::empty()).unwrap();
    let response = app.oneshot(whoami).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-surge-account"], accounts[0]);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn concurrent_legacy_add_adopts_original_session_once() {
    let (old_app, service) = test_app(false).await;
    let (app, _) = test_app(true).await;
    let work = format!("work-{}", rand_suffix());
    let personal = format!("personal-{}", rand_suffix());
    let password = register_identity(&old_app, &service, &work).await;
    register_identity(&old_app, &service, &personal).await;

    async fn start(app: &axum::Router, uri: &str, cookie: &str) -> Value {
        let request = Request::get(uri)
            .header("accept", "application/json")
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        body_json(response).await
    }
    fn submit(flow: &Value, cookie: &str, username: &str, password: &str) -> Request<Body> {
        Request::post(format!(
            "/v1/flows/{}/password",
            flow["flow_id"].as_str().unwrap()
        ))
        .header("cookie", cookie)
        .header("origin", AUTH_UI_ORIGIN)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "username": username, "password": password, "csrf_token": flow["csrf_token"]
            })
            .to_string(),
        ))
        .unwrap()
    }
    async fn legacy_cookie(app: &axum::Router, owner: &str, password: &str) -> String {
        let flow = start(app, "/v1/login", "").await;
        let response = app.clone().oneshot(submit(&flow, "", owner, password)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned()
    }
    let legacy = legacy_cookie(&old_app, &work, &password).await;
    let inverse_legacy = legacy_cookie(&old_app, &personal, &password).await;
    let inverse = start(&app, "/v1/login?intent=add_account", &inverse_legacy).await;
    let first = start(&app, "/v1/login?intent=add_account", &legacy).await;
    let second = start(&app, "/v1/login?intent=add_account", &legacy).await;
    let response = app
        .clone()
        .oneshot(submit(&first, &legacy, &personal, "incorrect password"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let whoami = |cookie: &str| {
        Request::get("/v1/whoami")
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap()
    };
    let response = app.clone().oneshot(whoami(&legacy)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let old = body_json(response).await;
    let (a, b, reverse) = tokio::join!(
        app.clone()
            .oneshot(submit(&first, &legacy, &personal, &password)),
        app.clone()
            .oneshot(submit(&second, &legacy, &personal, &password)),
        app.clone().oneshot(submit(&inverse, &inverse_legacy, &work, &password)),
    );
    assert_eq!(reverse.unwrap().status(), StatusCode::OK);
    let (a, b) = (a.unwrap(), b.unwrap());
    let (winner, retired) = if a.status().is_success() {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!(winner.status(), StatusCode::OK);
    assert_eq!(winner.headers()["cache-control"], "no-store");
    assert_eq!(retired.status(), StatusCode::UNAUTHORIZED);
    let cookies = || {
        winner
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
    };
    assert!(cookies().any(|c| c.starts_with("surge_session=") && c.contains("Max-Age=0")));
    let browser = cookies()
        .find(|c| c.starts_with("surge_browser="))
        .unwrap()
        .split(';')
        .next()
        .unwrap().to_owned();
    let account = body_json(winner).await["account_id"].as_str().unwrap().to_owned();
    let mut selected = whoami(&browser);
    selected.headers_mut().insert("x-surge-account", account.parse().unwrap());
    let response = app.clone().oneshot(selected).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-surge-account"], account);
    assert_eq!(body_json(response).await["identity"]["username"], personal);
    let response = app.clone().oneshot(whoami(&browser)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let adopted = body_json(response).await;
    for field in ["id", "identity", "issued_at", "expires_at"] {
        assert_eq!(adopted[field], old[field]);
    }
    assert_eq!(
        app.oneshot(whoami(&legacy)).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL against a disposable Postgres"]
async fn redirect_login_hands_membership_only_to_live_picker_origins() {
    let (app, service, engine) = test_app_with_engine(true, false).await;
    let different_port = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("return_to", "https://app.canary.test:8443/services#surge_account")
        .finish();
    let start = Request::get(format!("/v1/login?{different_port}")).body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(start).await.unwrap().status(), StatusCode::UNPROCESSABLE_ENTITY);
    let suffix = rand_suffix();
    let work = format!("redirect-work-{suffix}");
    let other = format!("redirect-other-{suffix}");
    for name in [&work, &other] {
        register_identity(&app, &service, name).await;
    }

    let mut cookie = String::new();
    let mut default_id = String::new();
    let grant_name = format!("picker-{suffix}");
    for (index, (origin, fragment, authorized)) in [
        (AUTH_UI_ORIGIN, "surge_account", true),
        (AUTH_UI_ORIGIN, "surge_account", true),
        (RETURN_ORIGIN, "surge_account", true),
        (RETURN_ORIGIN, "surge_account", false),
        (RETURN_ORIGIN, "ordinary", false),
    ].into_iter().enumerate() {
        // Grant an existing return origin, then withdraw the grant while its
        // next flow is in flight. Its ordinary return registration remains.
        if index == 2 {
            engine.create_service(&grant_name,
                surge_engine::types::ServiceToken::generate().hash(),
                vec!["account_list".into()], vec![origin.into()]).await.unwrap();
        }
        let callback = format!("{origin}/services#{fragment}");
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        params.append_pair("return_to", &callback);
        if index > 0 { params.append_pair("intent", "add_account"); }
        let start = Request::get(format!("/v1/login?{}", params.finish()))
            .header("cookie", &cookie).body(Body::empty()).unwrap();
        let response = app.clone().oneshot(start).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let redirect = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
        assert_eq!(redirect.origin().ascii_serialization(), AUTH_UI_ORIGIN);
        let id = redirect.query_pairs().find(|(key, _)| key == "flow").unwrap().1;
        let get = Request::get(format!("/v1/flows/{id}")).header("cookie", &cookie)
            .body(Body::empty()).unwrap();
        let flow = body_json(app.clone().oneshot(get).await.unwrap()).await;
        if index == 3 {
            engine.revoke_service(&grant_name).await.unwrap();
        }
        let submit = Request::post(format!("/v1/flows/{id}/password"))
            .header("cookie", &cookie).header("content-type", "application/json")
            .body(Body::from(json!({
                "username": if index == 0 { &work } else { &other },
                "password": "correct horse battery staple", "csrf_token": flow["csrf_token"]
            }).to_string())).unwrap();
        let response = app.clone().oneshot(submit).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        if cookie.is_empty() {
            cookie = response.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().into();
        }
        let body = body_json(response).await;
        if authorized {
            let id = body["account_id"].as_str().unwrap();
            assert_eq!(body["return_to"], format!("{callback}={id}"));
            if index == 0 { default_id = id.into(); } else { assert_ne!(id, default_id); }
        } else {
            assert_eq!(body["return_to"], callback);
            if fragment == "surge_account" { assert!(body.get("account_id").is_none()); }
        }
    }
    let whoami = Request::get("/v1/whoami").header("cookie", cookie).body(Body::empty()).unwrap();
    let response = app.oneshot(whoami).await.unwrap();
    assert_eq!(response.headers()["x-surge-account"], default_id);
}
