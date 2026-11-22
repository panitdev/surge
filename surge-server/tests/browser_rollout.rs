//! The same browser contract runs directly against the embedded handlers and
//! through the deployed remote proxy. OAuth navigation always goes to the issuer.
mod oauth_support;
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
    response::Response,
};
use oauth_support::*;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use surge::{AuthProvider, RemoteConfig, RemoteProvider, router::BrowserRouterConfig};
use tower::ServiceExt;

async fn call(
    app: &Router,
    method: Method,
    path: &str,
    cookie: &str,
    pin: Option<&str>,
    body: Option<Value>,
) -> Response {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .extension(axum::extract::ConnectInfo(
            "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
        ))
        .header("origin", AUTH_UI_ORIGIN)
        .header("accept", "application/json")
        .header("cookie", cookie)
        .header("x-surge-csrf", "1");
    if let Some(pin) = pin {
        req = req.header("x-surge-account", pin);
    }
    let body = match body {
        Some(value) => {
            req = req.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    app.clone().oneshot(req.body(body).unwrap()).await.unwrap()
}

async fn proxy(h: &Harness) -> (Router, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let central = h.app.clone();
    let server = tokio::spawn(async move { axum::serve(listener, central).await.unwrap() });
    let service = surge_engine::types::ServiceToken::generate();
    h.engine
        .create_service(
            &format!("rollout-proxy-{}", h.suffix),
            service.hash(),
            vec!["browser_proxy".into()],
            vec![],
        )
        .await
        .unwrap();
    let remote = RemoteProvider::new(RemoteConfig {
        base_url,
        service_token: service.expose_secret().to_owned().into(),
        cache_ttl: Duration::from_secs(30),
        cache_max_entries: 10,
        timeout: Duration::from_secs(5),
    })
    .unwrap();
    (
        Arc::new(remote).browser_router(BrowserRouterConfig {
            cookie_domain: "oauth.test".into(),
            session_ttl: Duration::from_secs(3600),
            auth_ui_origin: AUTH_UI_ORIGIN.into(),
            session_cors_origins: vec![],
            browser_public_origin: None,
            rate_limiter: None,
            return_origins: None,
            registration: None,
            factor_policy: None,
            allow_inline: None,
            multi_account: false,
            oauth_as: None,
            maintenance_interval: None,
        }),
        server,
    )
}

async fn rollout(remote: bool) {
    let old = harness_mode(false, |s| s).await;
    let legacy = format!("surge_session={}", old.sign_in().await);
    let old_work =
        body_json(call(&old.app, Method::GET, "/v1/whoami", &legacy, None, None).await).await;
    assert_eq!(
        call(
            &old.app,
            Method::GET,
            "/v1/login?intent=add_account",
            &legacy,
            None,
            None
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let h = harness_mode(true, |s| s).await;
    let (app, server) = if remote {
        let (app, server) = proxy(&h).await;
        (app, Some(server))
    } else {
        (h.app.clone(), None)
    };
    let flow = body_json(
        call(
            &app,
            Method::GET,
            "/v1/login?intent=add_account",
            &legacy,
            None,
            None,
        )
        .await,
    )
    .await;
    assert!(
        flow["flow_id"].is_string(),
        "flow initialization failed: {:?}",
        flow["error"]
    );
    let register = format!("/v1/flows/{}/register", flow["flow_id"].as_str().unwrap());
    let personal_name = uuid::Uuid::now_v7().simple().to_string();
    let first_password = "correct horse battery staple";
    let response = call(&app,Method::POST,&register,&legacy,None,Some(json!({
        "username":personal_name,"display_name":"Personal","password":first_password,"csrf_token":flow["csrf_token"]
    }))).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let cookies: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("surge_session=") && c.contains("Max-Age=0"))
    );
    let cookie = cookies
        .iter()
        .find(|c| c.starts_with("surge_browser="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(
        call(&app, Method::GET, "/v1/whoami", &legacy, None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let retired = call(&app, Method::POST, "/v1/logout", &legacy, None, None).await;
    assert_eq!(retired.status(), StatusCode::UNAUTHORIZED);
    assert!(!retired.headers().contains_key("set-cookie"));
    let separate = h
        .engine
        .mint_session(old.identity_id().await, surge::AuthMethod::Password)
        .await
        .unwrap();
    let separate = format!("surge_session={}", separate.token.expose_secret());
    for credential in [separate.as_str(), separate.as_str(), ""] {
        assert_eq!(
            call(&app, Method::POST, "/v1/logout", credential, None, None)
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
    }
    let default = call(&app, Method::GET, "/v1/whoami", &cookie, None, None).await;
    let work = default.headers()["x-surge-account"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(body_json(default).await["id"], old_work["id"]);
    let write = "/v1/account/password";
    let adopted_work_password = "updated adopted Work password";
    assert_eq!(
        call(
            &app,
            Method::POST,
            write,
            &cookie,
            None,
            Some(json!({
                "step_up":first_password, "new_password":adopted_work_password
            }))
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let accounts =
        body_json(call(&app, Method::GET, "/v1/accounts", &cookie, None, None).await).await;
    let personal = accounts["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["identity"]["username"] == personal_name)
        .unwrap()["account_id"]
        .as_str()
        .unwrap();

    // The Work tab starts consent and opens a password form before the
    // Personal tab changes the default. Both requests carry the shared cookie.
    let client = h.client(false).await;
    let uri = h.authorize_uri(
        &client,
        &Pkce::generate(),
        Some(&h.resource_uri),
        Some("mcp:read"),
    );
    let consent = call(
        &h.app,
        Method::GET,
        &format!("{uri}&account_id={work}"),
        &cookie,
        None,
        None,
    )
    .await;
    let path = format!(
        "/v1/oauth/consent/{}",
        query_param(&location(&consent), "consent_flow").unwrap()
    );
    let screen = body_json(call(&h.app, Method::GET, &path, &cookie, None, None).await).await;
    assert!(
        call(
            &app,
            Method::PUT,
            "/v1/accounts/default",
            &cookie,
            None,
            Some(json!({"account_id":personal}))
        )
        .await
        .status()
        .is_success()
    );
    for (pin, current_password, new_password) in [
        (
            Some(work.as_str()),
            adopted_work_password,
            "changed Work password",
        ),
        (None, first_password, "changed Personal password"),
    ] {
        let response = call(
            &app,
            Method::POST,
            write,
            &cookie,
            pin,
            Some(json!({"step_up":current_password,"new_password":new_password})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
    for (pin, password) in [
        (&work[..], "changed Work password"),
        (personal, "changed Personal password"),
    ] {
        let info =
            body_json(call(&app, Method::GET, "/v1/whoami", &cookie, Some(pin), None).await).await;
        let identity =
            surge::IdentityId::from_uuid(info["identity"]["id"].as_str().unwrap().parse().unwrap());
        h.engine
            .verify_password_by_id(
                identity,
                &surge::Password::new(password.to_owned().into()).unwrap(),
            )
            .await
            .unwrap();
    }
    let decision = body_json(
        call(
            &h.app,
            Method::POST,
            &path,
            &cookie,
            None,
            Some(json!({"approve":true,"csrf_token":screen["csrf_token"]})),
        )
        .await,
    )
    .await;
    let code = query_param(decision["redirect_to"].as_str().unwrap(), "code").unwrap();
    let grant = h
        .engine
        .consume_authorization_code(
            &surge_engine::AuthorizationCode::from_raw(&code).unwrap(),
            &client,
        )
        .await
        .unwrap();
    assert_eq!(grant.session_id.to_string(), old_work["id"]);
    let personal_consent = call(
        &h.app,
        Method::GET,
        &format!("{uri}&account_id={personal}"),
        &cookie,
        None,
        None,
    )
    .await;
    let personal_path = format!(
        "/v1/oauth/consent/{}",
        query_param(&location(&personal_consent), "consent_flow").unwrap()
    );
    let pending =
        body_json(call(&h.app, Method::GET, &personal_path, &cookie, None, None).await).await;
    assert!(
        call(&app, Method::POST, "/v1/logout", &cookie, None, None)
            .await
            .status()
            .is_success()
    );
    for pin in [None, Some(personal)] {
        for (method, path, body) in [
            (Method::GET, "/v1/whoami", None),
            (
                Method::POST,
                write,
                Some(
                    json!({"step_up":"changed Personal password","new_password":"unavailable account"}),
                ),
            ),
            (Method::POST, "/v1/logout", None),
        ] {
            assert_eq!(
                call(&app, method, path, &cookie, pin, body).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }
    assert_eq!(
        call(&app, Method::GET, "/v1/whoami", &cookie, Some(&work), None)
            .await
            .status(),
        StatusCode::OK
    );
    // A live default must never be substituted for a removed pin.
    assert!(
        call(
            &app,
            Method::PUT,
            "/v1/accounts/default",
            &cookie,
            None,
            Some(json!({"account_id":work}))
        )
        .await
        .status()
        .is_success()
    );
    assert_eq!(
        call(
            &app,
            Method::POST,
            write,
            &cookie,
            Some(personal),
            Some(json!({"step_up":"changed Work password","new_password":"unavailable account"}))
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let unavailable = call(
        &h.app,
        Method::GET,
        &format!("{uri}&account_id={personal}"),
        &cookie,
        None,
        None,
    )
    .await;
    assert_eq!(
        query_param(&location(&unavailable), "error").as_deref(),
        Some("login_required")
    );
    let rejected = call(
        &h.app,
        Method::POST,
        &personal_path,
        &cookie,
        None,
        Some(json!({"approve":true,"csrf_token":pending["csrf_token"]})),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    if let Some(server) = server {
        server.abort();
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL via DATABASE_URL"]
async fn embedded_browser_rollout() {
    rollout(false).await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL via DATABASE_URL"]
async fn remote_browser_rollout() {
    rollout(true).await;
}
