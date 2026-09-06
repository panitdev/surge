//! `POST /oauth2/token` (internal/oauth-as.md §5.4, §7, §11).

mod oauth_support;

use axum::http::StatusCode;
use oauth_support::*;
use serde_json::Value;

async fn exchange(h: &Harness, client_id: &str, code: &str, pkce: &Pkce) -> (StatusCode, Value) {
    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", CLIENT_REDIRECT),
                ("client_id", client_id),
                ("code_verifier", &pkce.verifier),
            ],
        )
        .await;
    let status = resp.status();
    (status, body_json(resp).await)
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_code_becomes_an_audience_restricted_access_token() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();

    let code = h.authorize_code(&client_id, &session, &pkce).await;
    let (status, body) = exchange(&h, &client_id, &code, &pkce).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "mcp:read");
    assert!(body["refresh_token"].as_str().unwrap().starts_with("aeg_rt_"));

    // The claims are the contract a resource server verifies against.
    let claims = decode_claims(body["access_token"].as_str().unwrap());
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["aud"], h.resource_uri);
    assert_eq!(claims["client_id"], client_id);
    assert_eq!(claims["sub"], h.identity_id().await.to_string());
    assert!(claims["sid"].as_str().is_some());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_code_is_redeemable_exactly_once() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();

    let code = h.authorize_code(&client_id, &session, &pkce).await;
    let (first, _) = exchange(&h, &client_id, &code, &pkce).await;
    assert_eq!(first, StatusCode::OK);

    let (second, body) = exchange(&h, &client_id, &code, &pkce).await;
    assert_eq!(second, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

/// The single-use property is settled in the database, so it has to hold when
/// two exchanges race rather than merely when they are sequential.
#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn concurrent_redemptions_of_one_code_produce_exactly_one_token() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();
    let code = h.authorize_code(&client_id, &session, &pkce).await;

    let attempts = (0..6).map(|_| exchange(&h, &client_id, &code, &pkce));
    let results = futures_util::future::join_all(attempts).await;

    let successes = results
        .iter()
        .filter(|(status, _)| *status == StatusCode::OK)
        .count();
    assert_eq!(successes, 1, "exactly one redemption may succeed");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn the_redirect_uri_must_match_the_one_the_code_was_issued_for() {
    let h = harness().await;
    let session = h.sign_in().await;
    let (client_id, _) = h
        .client_with(
            true,
            vec![
                CLIENT_REDIRECT.to_string(),
                "https://client.oauth.test/other".to_string(),
            ],
            false,
        )
        .await;
    let pkce = Pkce::generate();
    let code = h.authorize_code(&client_id, &session, &pkce).await;

    // Both URIs are registered for this client, so only the per-code match
    // stops one from redeeming a code issued against the other.
    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://client.oauth.test/other"),
                ("client_id", &client_id),
                ("code_verifier", &pkce.verifier),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_code_stolen_by_another_client_is_worthless() {
    let h = harness().await;
    let session = h.sign_in().await;
    let victim = h.client(true).await;
    let thief = h.client(true).await;
    let pkce = Pkce::generate();

    let code = h.authorize_code(&victim, &session, &pkce).await;
    let (status, body) = exchange(&h, &thief, &code, &pkce).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_wrong_pkce_verifier_is_refused() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();
    let code = h.authorize_code(&client_id, &session, &pkce).await;

    let other = Pkce::generate();
    let (status, body) = exchange(&h, &client_id, &code, &other).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn refresh_rotates_and_reuse_kills_the_whole_family() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();
    let code = h.authorize_code(&client_id, &session, &pkce).await;

    let (_, first) = exchange(&h, &client_id, &code, &pkce).await;
    let refresh_one = first["refresh_token"].as_str().unwrap().to_string();

    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_one),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let second = body_json(resp).await;
    let refresh_two = second["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(refresh_one, refresh_two, "refresh tokens must rotate");

    // Replaying the consumed token is the stolen-token signal: the successor
    // dies with it, so the grant ends rather than being shared.
    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_one),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_two),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "reuse must revoke the successor too, not just the replayed token"
    );
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_refresh_may_narrow_scope_but_never_widen_it() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();
    let code = h.authorize_code(&client_id, &session, &pkce).await;
    let (_, first) = exchange(&h, &client_id, &code, &pkce).await;
    let refresh = first["refresh_token"].as_str().unwrap().to_string();

    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &client_id),
                ("scope", "mcp:read mcp:write"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_scope");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn unsupported_grant_types_are_refused_by_name() {
    let h = harness().await;
    let client_id = h.client(true).await;

    for grant in ["client_credentials", "password", "implicit"] {
        let resp = h
            .post_form(
                "/oauth2/token",
                &[("grant_type", grant), ("client_id", &client_id)],
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{grant} was accepted");
        assert_eq!(body_json(resp).await["error"], "unsupported_grant_type");
    }
}

/// Decodes the claims without verifying — the signature is JWKS's business
/// (see `oauth_keys.rs`); this is about what the claims *say*.
fn decode_claims(token: &str) -> Value {
    use base64::Engine as _;

    let payload = token.split('.').nth(1).expect("not a JWT");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("payload is not base64url");
    serde_json::from_slice(&bytes).expect("payload is not JSON")
}
