//! The third-party consent round trip and account connections
//! (internal/oauth-as.md §5.2, §11).

mod oauth_support;

use axum::http::StatusCode;
use oauth_support::*;
use serde_json::json;

/// Drives authorize far enough to get a consent flow id.
async fn start_consent(h: &Harness, client_id: &str, session: &str, pkce: &Pkce) -> String {
    let resp = h
        .get(
            &h.authorize_uri(client_id, pkce, Some(&h.resource_uri), Some("mcp:read")),
            Some(session),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let target = location(&resp);
    query_param(&target, "consent_flow").expect("no consent_flow in the redirect")
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn the_consent_screen_is_told_the_client_registered_itself() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(false).await;
    let pkce = Pkce::generate();
    let flow_id = start_consent(&h, &client_id, &session, &pkce).await;

    let resp = h
        .get(&format!("/v1/oauth/consent/{flow_id}"), Some(&session))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;

    assert_eq!(body["client"]["client_id"], client_id);
    // Admin-registered here, but the field must be present either way: a UI
    // that cannot tell a self-declared name from a verified one trains people
    // to approve anything.
    assert_eq!(body["client"]["dynamically_registered"], false);
    assert_eq!(body["resource"]["resource_uri"], h.resource_uri);
    assert_eq!(body["scopes"][0]["scope"], "mcp:read");
    assert_eq!(body["scopes"][0]["description"], "Read your data");
    assert!(body["csrf_token"].as_str().is_some());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_consent_flow_is_not_readable_by_anyone_else() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(false).await;
    let pkce = Pkce::generate();
    let flow_id = start_consent(&h, &client_id, &session, &pkce).await;

    let resp = h.get(&format!("/v1/oauth/consent/{flow_id}"), None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn approval_mints_a_code_persists_consent_and_is_not_asked_again() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(false).await;
    let pkce = Pkce::generate();
    let flow_id = start_consent(&h, &client_id, &session, &pkce).await;

    let flow = body_json(
        h.get(&format!("/v1/oauth/consent/{flow_id}"), Some(&session))
            .await,
    )
    .await;
    let csrf = flow["csrf_token"].as_str().unwrap().to_string();

    let resp = h
        .post_json(
            &format!("/v1/oauth/consent/{flow_id}"),
            json!({ "approve": true, "csrf_token": csrf }),
            Some(&session),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let redirect = body_json(resp).await["redirect_to"].as_str().unwrap().to_string();
    assert!(redirect.starts_with(CLIENT_REDIRECT));
    assert!(query_param(&redirect, "code").is_some());
    assert_eq!(query_param(&redirect, "state").as_deref(), Some("xyz"));

    // A decided flow is spent: replaying the approval would be a code-minting
    // oracle.
    let resp = h
        .post_json(
            &format!("/v1/oauth/consent/{flow_id}"),
            json!({ "approve": true, "csrf_token": csrf }),
            Some(&session),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // The stored consent means the next authorize goes straight through.
    let next = Pkce::generate();
    let resp = h
        .get(
            &h.authorize_uri(&client_id, &next, Some(&h.resource_uri), Some("mcp:read")),
            Some(&session),
        )
        .await;
    let target = location(&resp);
    assert!(
        query_param(&target, "code").is_some(),
        "consent should not be asked twice, got {target}"
    );
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn denial_returns_access_denied_to_the_client() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(false).await;
    let pkce = Pkce::generate();
    let flow_id = start_consent(&h, &client_id, &session, &pkce).await;

    let flow = body_json(
        h.get(&format!("/v1/oauth/consent/{flow_id}"), Some(&session))
            .await,
    )
    .await;
    let csrf = flow["csrf_token"].as_str().unwrap().to_string();

    let resp = h
        .post_json(
            &format!("/v1/oauth/consent/{flow_id}"),
            json!({ "approve": false, "csrf_token": csrf }),
            Some(&session),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let redirect = body_json(resp).await["redirect_to"].as_str().unwrap().to_string();
    assert_eq!(query_param(&redirect, "error").as_deref(), Some("access_denied"));
    assert!(query_param(&redirect, "code").is_none());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_bad_csrf_token_cannot_approve() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(false).await;
    let pkce = Pkce::generate();
    let flow_id = start_consent(&h, &client_id, &session, &pkce).await;

    let resp = h
        .post_json(
            &format!("/v1/oauth/consent/{flow_id}"),
            json!({ "approve": true, "csrf_token": "not-the-token" }),
            Some(&session),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn approving_a_scope_that_was_never_requested_is_refused() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(false).await;
    let pkce = Pkce::generate();
    let flow_id = start_consent(&h, &client_id, &session, &pkce).await;

    let flow = body_json(
        h.get(&format!("/v1/oauth/consent/{flow_id}"), Some(&session))
            .await,
    )
    .await;
    let csrf = flow["csrf_token"].as_str().unwrap().to_string();

    let resp = h
        .post_json(
            &format!("/v1/oauth/consent/{flow_id}"),
            json!({
                "approve": true,
                "scopes": ["mcp:read", "mcp:write"],
                "csrf_token": csrf,
            }),
            Some(&session),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn disconnecting_an_app_kills_its_refresh_tokens() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(false).await;
    let pkce = Pkce::generate();
    let flow_id = start_consent(&h, &client_id, &session, &pkce).await;

    let flow = body_json(
        h.get(&format!("/v1/oauth/consent/{flow_id}"), Some(&session))
            .await,
    )
    .await;
    let csrf = flow["csrf_token"].as_str().unwrap().to_string();
    let redirect = body_json(
        h.post_json(
            &format!("/v1/oauth/consent/{flow_id}"),
            json!({ "approve": true, "csrf_token": csrf }),
            Some(&session),
        )
        .await,
    )
    .await["redirect_to"]
        .as_str()
        .unwrap()
        .to_string();
    let code = query_param(&redirect, "code").unwrap();

    let tokens = body_json(
        h.post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", CLIENT_REDIRECT),
                ("client_id", &client_id),
                ("code_verifier", &pkce.verifier),
            ],
        )
        .await,
    )
    .await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();

    // The app is listed where the user can see it.
    let listed = body_json(h.get("/v1/account/connections", Some(&session)).await).await;
    assert_eq!(listed["connections"][0]["client_id"], client_id);

    let resp = h
        .delete(&format!("/v1/account/connections/{client_id}"), &session)
        .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Disconnecting is only meaningful if the tokens die with the consent.
    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let listed = body_json(h.get("/v1/account/connections", Some(&session)).await).await;
    assert_eq!(listed["connections"].as_array().unwrap().len(), 0);
}
