mod oauth_support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use oauth_support::*;
use serde_json::{json, Value};
use surge_engine::{
    AuthorizationCode, BrowserSessionToken, CompletedLogin, Password, RegisterRequest, Username,
    VerifiedLogin,
};
use tower::ServiceExt;

fn password() -> Password {
    Password::new("authorization binding test password".to_owned().into()).unwrap()
}

async fn member(
    h: &Harness,
    token: Option<&BrowserSessionToken>,
    login: VerifiedLogin,
) -> CompletedLogin {
    let flow = h
        .engine
        .create_browser_login_flow(None, token.is_some(), token, None)
        .await
        .unwrap();
    h.engine
        .finish_login_flow(
            &flow.id,
            &flow.csrf_token,
            token,
            None,
            true,
            login,
            "test_login",
            None,
        )
        .await
        .unwrap()
}

fn registration() -> VerifiedLogin {
    VerifiedLogin::Register(RegisterRequest {
        username: Username::new(&uuid::Uuid::now_v7().simple().to_string()).unwrap(),
        display_name: "OAuth test member".into(),
        password: password(),
    })
}

async fn request(
    h: &Harness,
    token: &BrowserSessionToken,
    uri: &str,
    decision: Option<Value>,
) -> Response {
    let mut req = Request::builder()
        .uri(uri)
        .header("cookie", format!("surge_browser={}", token.expose_secret()));
    let body = match decision {
        Some(json) => {
            req = req
                .method("POST")
                .header("origin", AUTH_UI_ORIGIN)
                .header("content-type", "application/json");
            Body::from(json.to_string())
        }
        None => Body::empty(),
    };
    h.app
        .clone()
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn consent_remains_bound_to_the_default_at_authorization() {
    let h = harness().await;
    let work = member(&h, None, registration()).await;
    let token = &work.browser_cookie.unwrap().token;
    let personal = member(&h, Some(token), registration()).await;
    let client = h.client(false).await;
    let uri = h.authorize_uri(
        &client,
        &Pkce::generate(),
        Some(&h.resource_uri),
        Some("mcp:read"),
    );
    let flow = query_param(
        &location(&request(&h, token, &uri, None).await),
        "consent_flow",
    )
    .unwrap();
    h.engine
        .set_default_account(token, personal.account_id.unwrap())
        .await
        .unwrap();
    let path = format!("/v1/oauth/consent/{flow}");
    let screen = body_json(request(&h, token, &path, None).await).await;
    let response = request(
        &h,
        token,
        &path,
        Some(json!({"approve":true, "csrf_token":screen["csrf_token"]})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let code = query_param(body["redirect_to"].as_str().unwrap(), "code").unwrap();
    let grant = h
        .engine
        .consume_authorization_code(&AuthorizationCode::from_raw(&code).unwrap(), &client)
        .await
        .unwrap();
    assert_eq!(grant.session_id, *work.issued.session.id.as_uuid());

    let pinned = format!("{uri}&account_id={}&prompt=none", work.account_id.unwrap());
    let response = request(&h, token, &pinned, None).await;
    assert!(query_param(&location(&response), "code").is_some());
    for account in ["invalid".into(), uuid::Uuid::now_v7().to_string()] {
        let response = request(&h, token, &format!("{uri}&account_id={account}"), None).await;
        let target = location(&response);
        assert!(target.starts_with(CLIENT_REDIRECT));
        assert_eq!(
            query_param(&target, "error").as_deref(),
            Some("login_required")
        );
        assert_eq!(query_param(&target, "state").as_deref(), Some("xyz"));
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn invalidated_members_cannot_finish_consent() {
    let h = harness().await;
    let client = h.client(false).await;
    let uri = h.authorize_uri(
        &client,
        &Pkce::generate(),
        Some(&h.resource_uri),
        Some("mcp:read"),
    );
    let mut conn = AsyncPgConnection::establish(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    for change in ["expiry", "revocation", "reauthentication"] {
        let work = member(&h, None, registration()).await;
        let token = &work.browser_cookie.unwrap().token;
        let account = work.account_id.unwrap();
        let flow = query_param(
            &location(&request(&h, token, &format!("{uri}&account_id={account}"), None).await),
            "consent_flow",
        )
        .unwrap();
        let path = format!("/v1/oauth/consent/{flow}");
        let screen = body_json(request(&h, token, &path, None).await).await;
        match change {
            "expiry" => {
                use surge_engine::schema::session;
                diesel::update(session::table.find(work.issued.session.id.as_uuid()))
                    .set(session::expires_at.eq(chrono::Utc::now()))
                    .execute(&mut conn)
                    .await
                    .unwrap();
            }
            "revocation" => {
                h.engine
                    .remove_browser_account(token, account, None)
                    .await
                    .unwrap();
            }
            _ => {
                let (_, proof) = h
                    .engine
                    .verify_login_password(&work.issued.session.identity.username, &password())
                    .await
                    .unwrap();
                let replacement = member(&h, Some(token), VerifiedLogin::Password(proof)).await;
                assert_eq!(replacement.account_id, Some(account));
            }
        }
        // Exercise the same last check for a grant that skipped the consent screen.
        let grant = surge_engine::oauth::AuthorizationGrant {
            client_id: client.clone(),
            identity_id: work.issued.session.identity.id,
            session_id: *work.issued.session.id.as_uuid(),
            resource_uri: h.resource_uri.clone(),
            redirect_uri: CLIENT_REDIRECT.into(),
            scopes: vec!["mcp:read".into()],
            code_challenge: Pkce::generate().challenge,
            code_challenge_method: "S256".into(),
            nonce: None,
        };
        let binding = surge_engine::oauth::AuthorizationSession::Member(token.clone(), account);
        assert!(matches!(
            h.engine
                .mint_authorization_code(&grant, &binding, None)
                .await,
            Err(surge_engine::AuthError::InvalidToken)
        ));
        for decision in [
            None,
            Some(json!({"approve":true, "csrf_token":screen["csrf_token"]})),
        ] {
            let response = request(&h, token, &path, decision).await;
            assert!(
                matches!(
                    response.status(),
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                ),
                "{change}: {}",
                response.status()
            );
        }
        assert!(h
            .engine
            .find_consent(&client, work.issued.session.identity.id, &h.resource_uri)
            .await
            .unwrap()
            .is_none());
    }
}
