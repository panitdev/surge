mod oauth_support;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use oauth_support::*;
use serde_json::{Value, json};
use surge_engine::{AuthorizationCode, BrowserSessionToken};
use tower::ServiceExt;

async fn send(h: &Harness, path: &str, cookie: &str, body: Option<Value>, csrf: bool) -> Response {
    let mut req = Request::builder()
        .uri(path)
        .header("cookie", cookie)
        .header("origin", AUTH_UI_ORIGIN);
    if csrf {
        req = req.header("x-surge-csrf", "1");
    }
    let body = match body {
        Some(body) => {
            req = req
                .method("POST")
                .header("content-type", "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    h.app
        .clone()
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap()
}

fn browser_cookie(response: &Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|h| h.to_str().unwrap().split(';').next().unwrap())
        .find(|s| s.starts_with("surge_browser="))
        .unwrap()
        .to_owned()
}

async fn register(h: &Harness, login: &str, cookie: &str) -> Response {
    let id = query_param(login, "flow").unwrap();
    let path = format!("/v1/flows/{id}");
    let flow = body_json(send(h, &path, cookie, None, false).await).await;
    let name = uuid::Uuid::now_v7().simple().to_string();
    let response = send(h,&format!("{path}/register"),cookie,Some(json!({"csrf_token":flow["csrf_token"],"username":name,"display_name":name,"password":"long enough test password"})),false).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    response
}

async fn verify_code(h: &Harness, client: &str, target: &str, expected: &str) {
    assert!(target.starts_with(CLIENT_REDIRECT));
    assert_eq!(query_param(target, "state").as_deref(), Some("xyz"));
    let code = query_param(target, "code").unwrap();
    let grant = h
        .engine
        .consume_authorization_code(&AuthorizationCode::from_raw(&code).unwrap(), client)
        .await
        .unwrap();
    assert_eq!(grant.session_id.to_string(), expected);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn picker_and_normal_hosted_login_resume_once_with_exact_account() {
    let h = harness_mode(true, |s| s).await;
    let client = h.client(true).await;
    let uri = h.authorize_uri(
        &client,
        &Pkce::generate(),
        Some(&h.resource_uri),
        Some("mcp:read"),
    );
    let none = h.get(&format!("{uri}&prompt=none"), None).await;
    assert_eq!(
        query_param(&location(&none), "error").as_deref(),
        Some("login_required")
    );
    assert!(!none.headers().contains_key("set-cookie"));
    let conflict = h
        .get(&format!("{uri}&prompt=select_account&account_id=x"), None)
        .await;
    assert_eq!(
        query_param(&location(&conflict), "error").as_deref(),
        Some("invalid_request")
    );

    let login = h.get(&uri, None).await;
    let empty = browser_cookie(&login);
    let work = register(&h, &location(&login), &empty).await;
    let cookie = browser_cookie(&work);
    assert_ne!(empty, cookie);
    let work = body_json(work).await;
    let resume = work["return_to"].as_str().unwrap();
    assert_eq!(
        send(&h, resume, &empty, None, false).await.status(),
        StatusCode::UNAUTHORIZED
    );
    verify_code(
        &h,
        &client,
        &location(&send(&h, resume, &cookie, None, false).await),
        work["session"]["id"].as_str().unwrap(),
    )
    .await;
    assert_eq!(
        send(&h, resume, &cookie, None, false).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let picker = format!("{uri}&prompt=select_account");
    let target = location(&send(&h, &picker, &cookie, None, false).await);
    assert!(target.starts_with(&format!("{AUTH_UI_ORIGIN}/choose-account?")));
    let path = format!(
        "/v1/oauth/authorization-requests/{}/account",
        query_param(&target, "request_id").unwrap()
    );
    let another = Some(json!({"use_another_account":true}));
    assert_eq!(
        send(&h, &path, &cookie, another.clone(), false)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let other = h.engine.create_chooser_browser().await.unwrap();
    let foreign = format!("surge_browser={}", other.token.expose_secret());
    assert_eq!(
        send(&h, &path, &foreign, another.clone(), true)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let login = body_json(send(&h, &path, &cookie, another.clone(), true).await).await;
    assert_eq!(
        send(&h, &path, &cookie, another, true).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let personal =
        body_json(register(&h, login["redirect_to"].as_str().unwrap(), &cookie).await).await;
    verify_code(
        &h,
        &client,
        &location(
            &send(
                &h,
                personal["return_to"].as_str().unwrap(),
                &cookie,
                None,
                false,
            )
            .await,
        ),
        personal["session"]["id"].as_str().unwrap(),
    )
    .await;
    // Removing the default leaves one live member and requires an interactive choice.
    let token =
        BrowserSessionToken::from_raw(cookie.strip_prefix("surge_browser=").unwrap()).unwrap();
    h.engine
        .remove_browser_account(
            &token,
            work["account_id"].as_str().unwrap().parse().unwrap(),
            None,
        )
        .await
        .unwrap();
    let target = location(&send(&h, &uri, &cookie, None, false).await);
    let path = format!(
        "/v1/oauth/authorization-requests/{}/account",
        query_param(&target, "request_id").unwrap()
    );
    let choice = Some(json!({"account_id": personal["account_id"]}));
    let (a, b) = tokio::join!(
        send(&h, &path, &cookie, choice.clone(), true),
        send(&h, &path, &cookie, choice, true)
    );
    let (win, lose) = if a.status() == StatusCode::OK {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!(lose.status(), StatusCode::UNAUTHORIZED);
    verify_code(
        &h,
        &client,
        body_json(win).await["redirect_to"].as_str().unwrap(),
        personal["session"]["id"].as_str().unwrap(),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn legacy_picker_preserves_legacy_cookie_and_adopts_only_on_successful_add() {
    let h = harness_mode(true, |s| s).await;
    let name = surge_engine::Username::new(&uuid::Uuid::now_v7().simple().to_string()).unwrap();
    let identity = h.engine.create_identity(&name, "Legacy").await.unwrap();
    let legacy = h
        .engine
        .mint_session(identity.id, surge_engine::AuthMethod::Password)
        .await
        .unwrap();
    let cookie = format!("surge_session={}", legacy.token.expose_secret());
    let client = h.client(true).await;
    let uri = format!(
        "{}&prompt=select_account",
        h.authorize_uri(
            &client,
            &Pkce::generate(),
            Some(&h.resource_uri),
            Some("mcp:read")
        )
    );
    for another in [false, true] {
        let screen = send(&h, &uri, &cookie, None, false).await;
        assert!(!screen.headers().contains_key("set-cookie"));
        assert_eq!(
            send(&h, "/v1/whoami", &cookie, None, false).await.status(),
            StatusCode::OK
        );
        let id = query_param(&location(&screen), "request_id").unwrap();
        let path = format!("/v1/oauth/authorization-requests/{id}/account");
        let choice = if another {
            json!({"use_another_account":true})
        } else {
            json!({"use_current_account":true})
        };
        let target = body_json(send(&h, &path, &cookie, Some(choice), true).await).await;
        let target = target["redirect_to"].as_str().unwrap();
        if another {
            let completed = register(&h, target, &cookie).await;
            let new_cookie = browser_cookie(&completed);
            let data = body_json(completed).await;
            verify_code(
                &h,
                &client,
                &location(
                    &send(
                        &h,
                        data["return_to"].as_str().unwrap(),
                        &new_cookie,
                        None,
                        false,
                    )
                    .await,
                ),
                data["session"]["id"].as_str().unwrap(),
            )
            .await;
            assert_eq!(
                send(&h, "/v1/whoami", &cookie, None, false).await.status(),
                StatusCode::UNAUTHORIZED
            );
            for uri in [
                &uri[..],
                uri.strip_suffix("&prompt=select_account").unwrap(),
            ] {
                let stale = send(&h, uri, &cookie, None, false).await;
                assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
                assert!(!stale.headers().contains_key("set-cookie"));
            }
            assert_eq!(
                body_json(send(&h, "/v1/whoami", &new_cookie, None, false).await).await["id"],
                legacy.session.id.to_string()
            );
        } else {
            verify_code(&h, &client, target, &legacy.session.id.to_string()).await;
        }
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn explicit_empty_picker_expires_and_third_party_choice_reaches_consent() {
    use diesel::prelude::*;
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
    use surge_engine::schema::oauth_authorization_request as stored;
    let h = harness_mode(true, |s| s).await;
    let client = h.client(false).await;
    let uri = format!(
        "{}&prompt=select_account",
        h.authorize_uri(
            &client,
            &Pkce::generate(),
            Some(&h.resource_uri),
            Some("mcp:read")
        )
    );
    let screen = h.get(&uri, None).await;
    let cookie = browser_cookie(&screen);
    let id = query_param(&location(&screen), "request_id").unwrap();
    let mut conn = AsyncPgConnection::establish(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    diesel::update(stored::table.find(&id))
        .set(stored::expires_at.eq(chrono::Utc::now()))
        .execute(&mut conn)
        .await
        .unwrap();
    let path = format!("/v1/oauth/authorization-requests/{id}/account");
    assert_eq!(
        send(
            &h,
            &path,
            &cookie,
            Some(json!({"use_another_account":true})),
            true
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let id = query_param(
        &location(&send(&h, &uri, &cookie, None, false).await),
        "request_id",
    )
    .unwrap();
    let path = format!("/v1/oauth/authorization-requests/{id}/account");
    let login = body_json(
        send(
            &h,
            &path,
            &cookie,
            Some(json!({"use_another_account":true})),
            true,
        )
        .await,
    )
    .await;
    let completed = register(&h, login["redirect_to"].as_str().unwrap(), &cookie).await;
    let cookie = browser_cookie(&completed);
    let data = body_json(completed).await;
    let target = location(
        &send(
            &h,
            data["return_to"].as_str().unwrap(),
            &cookie,
            None,
            false,
        )
        .await,
    );
    let consent = query_param(&target, "consent_flow").unwrap();
    let path = format!("/v1/oauth/consent/{consent}");
    let screen = body_json(send(&h, &path, &cookie, None, false).await).await;
    let decision = body_json(
        send(
            &h,
            &path,
            &cookie,
            Some(json!({"approve":true,"csrf_token":screen["csrf_token"]})),
            false,
        )
        .await,
    )
    .await;
    verify_code(
        &h,
        &client,
        decision["redirect_to"].as_str().unwrap(),
        data["session"]["id"].as_str().unwrap(),
    )
    .await;
}
