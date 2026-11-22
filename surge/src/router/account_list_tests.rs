use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use surge_engine::{
    oauth::{NewOauthClient, RegistrationSource},
    ServiceToken,
};
use tower::ServiceExt;
use uuid::Uuid;

use super::{proxy_browser_router, BrowserRouterConfig, PostgresRateLimiter, ProxyConfig};
use crate::{AuthProvider, EmbeddedConfig, EmbeddedProvider};

async fn request(
    app: &Router,
    origin: &str,
    same_origin: bool,
    method: Method,
) -> axum::response::Response {
    let mut req = Request::builder().uri("/v1/accounts").method(method);
    req = if same_origin {
        req.header("sec-fetch-site", "same-origin")
            .header("referer", format!("{origin}/settings"))
    } else {
        req.header(header::ORIGIN, origin)
    };
    app.clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL DATABASE_URL"]
async fn list_grants_apply_directly_and_through_proxy() {
    let provider = Arc::new(
        EmbeddedProvider::new(EmbeddedConfig {
            database_url: std::env::var("DATABASE_URL").unwrap().into(),
            pepper: "test-pepper".to_owned().into(),
            session_ttl: Duration::from_secs(3600),
        })
        .await
        .unwrap(),
    );
    let engine = provider.engine();
    let name = Uuid::now_v7().simple().to_string();
    let granted = format!("https://{name}.example");
    let missing = format!("https://ungranted-{name}.example");
    let oauth_only = format!("https://oauth-{name}.example");
    let hosted = "https://auth.example";
    let proxy_token = ServiceToken::generate();
    engine
        .create_service(
            &format!("{name}-proxy"),
            proxy_token.hash(),
            vec!["browser_proxy".into()],
            vec![missing.clone()],
        )
        .await
        .unwrap();
    engine
        .create_service(
            &name,
            ServiceToken::generate().hash(),
            vec!["account_list".into()],
            vec![granted.clone()],
        )
        .await
        .unwrap();
    engine
        .create_oauth_client(NewOauthClient {
            client_name: name.clone(),
            client_uri: Some(oauth_only.clone()),
            logo_uri: None,
            redirect_uris: vec![format!("{oauth_only}/callback")],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["openid".into()],
            confidential: false,
            first_party: true,
            registration_source: RegistrationSource::Admin,
        })
        .await
        .unwrap();
    let direct = provider.browser_router(BrowserRouterConfig {
        cookie_domain: "example".into(),
        session_ttl: Duration::from_secs(3600),
        auth_ui_origin: hosted.into(),
        session_cors_origins: vec![missing.clone()],
        rate_limiter: Some(Arc::new(PostgresRateLimiter::new(
            engine.clone(),
            Default::default(),
        ))),
        return_origins: Some(vec![missing.clone()]),
        registration: None,
        factor_policy: None,
        allow_inline: None,
        multi_account: true,
        maintenance_interval: Some(Duration::ZERO),
        #[cfg(feature = "oauth-as")]
        oauth_as: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = direct.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, server).await.unwrap();
    });
    let proxy = proxy_browser_router(ProxyConfig {
        upstream_base_url: upstream,
        cookie_domain: "example".into(),
        auth_ui_origin: hosted.into(),
        session_cors_origins: vec![missing.clone()],
        service_token: proxy_token.expose_secret().to_owned().into(),
        client: reqwest::Client::new(),
    });
    for app in [&direct, &proxy] {
        for same_origin in [false, true] {
            for origin in [&missing, &oauth_only, &format!("{granted}:8443")] {
                let response = request(app, origin, same_origin, Method::GET).await;
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                assert!(!response
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            }
            for origin in [hosted, &granted] {
                for method in [Method::OPTIONS, Method::GET] {
                    let response = request(app, origin, same_origin, method.clone()).await;
                    assert!(response.status().is_success());
                    assert_eq!(
                        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
                        origin
                    );
                    assert_eq!(
                        response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
                        "true"
                    );
                    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                    if method == Method::GET {
                        let body = axum::body::to_bytes(response.into_body(), 8192)
                            .await
                            .unwrap();
                        assert_eq!(
                            serde_json::from_slice::<Value>(&body).unwrap(),
                            json!({"accounts": [], "default_account_id": null})
                        );
                    }
                }
            }
        }
    }
    let mut browser = None;
    let mut expected = Vec::new();
    for label in ["work", "personal"] {
        let token = browser
            .as_ref()
            .map(|b: &surge_engine::IssuedBrowserSession| &b.token);
        let flow = engine
            .create_browser_login_flow(None, token.is_some(), token, None)
            .await
            .unwrap();
        let username = Uuid::now_v7().simple().to_string();
        let login = surge_engine::VerifiedLogin::Register(surge_engine::RegisterRequest {
            username: surge_engine::Username::new(&username).unwrap(),
            password: surge_engine::Password::new(
                "account listing test password".to_owned().into(),
            )
            .unwrap(),
            display_name: label.to_owned(),
        });
        let completed = engine
            .finish_login_flow(
                &flow.id,
                &flow.csrf_token,
                token,
                None,
                true,
                login,
                "register",
                None,
            )
            .await
            .unwrap();
        expected.push(json!({
            "account_id": completed.account_id.unwrap(),
            "identity": {"id": completed.issued.session.identity.id, "username": username},
            "expires_at": completed.issued.session.expires_at,
        }));
        if browser.is_none() {
            browser = completed.browser_cookie;
        }
    }
    let browser = browser.unwrap();
    for app in [&direct, &proxy] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/accounts")
                    .header(header::ORIGIN, &granted)
                    .header(
                        header::COOKIE,
                        format!("surge_browser={}", browser.token.expose_secret()),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let list: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list["default_account_id"], expected[0]["account_id"]);
        let accounts = list["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 2);
        for item in &expected {
            let row = accounts
                .iter()
                .find(|a| a["account_id"] == item["account_id"])
                .unwrap();
            assert_eq!(row["identity"], item["identity"]);
            // PostgreSQL stores timestamps with microsecond precision.
            let expires = |v: &Value| {
                chrono::DateTime::parse_from_rfc3339(v.as_str().unwrap())
                    .unwrap()
                    .timestamp_micros()
            };
            assert_eq!(expires(&row["expires_at"]), expires(&item["expires_at"]));
        }
    }
    engine.revoke_service(&name).await.unwrap();
    for app in [&direct, &proxy] {
        assert_eq!(
            request(app, &granted, false, Method::GET).await.status(),
            StatusCode::FORBIDDEN
        );
    }
    task.abort();
}
