//! `GET /oauth2/authorize` (internal/oauth-as.md §5.1, §11).
//!
//! The properties here are the ones a mistake in this handler turns into a
//! vulnerability rather than a bug: redirect-URI exact match, mandatory PKCE,
//! audience validation, scope narrowing, and the session bounce.

mod oauth_support;

use axum::http::StatusCode;
use oauth_support::*;

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_redirect_uri_that_is_not_registered_is_never_redirected_to() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();

    let uri = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&resource={}",
        percent_encode(&client_id),
        percent_encode("https://evil.example/steal"),
        percent_encode(&pkce.challenge),
        percent_encode(&h.resource_uri),
    );
    let resp = h.get(&uri, Some(&session)).await;

    // The open-redirect test: an unvalidated redirect_uri must produce a
    // rendered error, never a 3xx of any kind.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get("location").is_none());
    assert!(body_text(resp).await.contains("invalid_redirect_uri"));
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn an_unknown_client_is_refused_without_a_redirect() {
    let h = harness().await;
    let pkce = Pkce::generate();
    let uri = h.authorize_uri("aeg_cid_nosuchclient00000000", &pkce, None, None);

    let resp = h.get(&uri, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get("location").is_none());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn pkce_is_mandatory_and_plain_is_refused() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;

    let base = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&resource={}&state=xyz",
        percent_encode(&client_id),
        percent_encode(CLIENT_REDIRECT),
        percent_encode(&h.resource_uri),
    );

    // No challenge at all.
    let resp = h.get(&base, Some(&session)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let target = location(&resp);
    assert!(target.starts_with(CLIENT_REDIRECT));
    assert_eq!(query_param(&target, "error").as_deref(), Some("invalid_request"));
    assert_eq!(query_param(&target, "state").as_deref(), Some("xyz"));

    // `plain`, which OAuth 2.1 removed and which offers no protection at all
    // against an intercepted code.
    let pkce = Pkce::generate();
    let resp = h
        .get(
            &format!(
                "{base}&code_challenge={}&code_challenge_method=plain",
                percent_encode(&pkce.verifier)
            ),
            Some(&session),
        )
        .await;
    let target = location(&resp);
    assert_eq!(query_param(&target, "error").as_deref(), Some("invalid_request"));
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn an_unregistered_audience_is_rejected_and_an_absent_one_is_required() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();

    let resp = h
        .get(
            &h.authorize_uri(&client_id, &pkce, Some("https://not.registered/mcp"), None),
            Some(&session),
        )
        .await;
    let target = location(&resp);
    assert_eq!(query_param(&target, "error").as_deref(), Some("invalid_target"));

    // SURGE_OAUTH_REQUIRE_RESOURCE defaults on: a token with no stated
    // audience is one that would validate anywhere.
    let resp = h
        .get(&h.authorize_uri(&client_id, &pkce, None, None), Some(&session))
        .await;
    let target = location(&resp);
    assert_eq!(query_param(&target, "error").as_deref(), Some("invalid_target"));
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_scope_the_resource_does_not_define_is_refused() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();

    let resp = h
        .get(
            &h.authorize_uri(
                &client_id,
                &pkce,
                Some(&h.resource_uri),
                Some("mcp:read mcp:root"),
            ),
            Some(&session),
        )
        .await;
    let target = location(&resp);
    assert_eq!(query_param(&target, "error").as_deref(), Some("invalid_scope"));
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn no_session_bounces_into_login_and_comes_back() {
    let h = harness().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();
    let uri = h.authorize_uri(&client_id, &pkce, Some(&h.resource_uri), Some("mcp:read"));

    let resp = h.get(&uri, None).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let target = location(&resp);
    assert!(
        target.starts_with(&format!("{ISSUER}/v1/login?return_to=")),
        "expected a login bounce, got {target}"
    );

    // The return_to points back at this same authorize URL, so the round trip
    // re-enters the handler once the session cookie is set.
    let return_to = query_param(&target, "return_to").expect("no return_to");
    assert!(return_to.starts_with(&format!("{ISSUER}/oauth2/authorize")));

    // And with a session, the same request now reaches a code.
    let session = h.sign_in().await;
    let resp = h.get(&uri, Some(&session)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let target = location(&resp);
    assert!(target.starts_with(CLIENT_REDIRECT));
    assert!(query_param(&target, "code").is_some());
    assert_eq!(query_param(&target, "state").as_deref(), Some("xyz"));
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_third_party_client_cannot_reach_a_code_without_consent() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(false).await;
    let pkce = Pkce::generate();

    let resp = h
        .get(
            &h.authorize_uri(&client_id, &pkce, Some(&h.resource_uri), Some("mcp:read")),
            Some(&session),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let target = location(&resp);
    assert!(
        target.starts_with(&format!("{AUTH_UI_ORIGIN}/consent?consent_flow=")),
        "a third-party client must reach a consent screen, got {target}"
    );
    assert!(query_param(&target, "code").is_none());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn prompt_none_refuses_rather_than_showing_a_screen() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(false).await;
    let pkce = Pkce::generate();

    let uri = format!(
        "{}&prompt=none",
        h.authorize_uri(&client_id, &pkce, Some(&h.resource_uri), Some("mcp:read"))
    );
    let resp = h.get(&uri, Some(&session)).await;
    let target = location(&resp);
    assert_eq!(
        query_param(&target, "error").as_deref(),
        Some("consent_required")
    );
}
