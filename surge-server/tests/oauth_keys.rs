//! Signing keys, JWKS, discovery and introspection
//! (internal/oauth-as.md §4, §5.4, §11).

mod oauth_support;

use axum::http::StatusCode;
use oauth_support::*;
use serde_json::json;

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn the_discovery_document_describes_this_server() {
    let h = harness().await;
    let body = body_json(h.get("/.well-known/oauth-authorization-server", None).await).await;

    assert_eq!(body["issuer"], ISSUER);
    assert_eq!(body["token_endpoint"], format!("{ISSUER}/oauth2/token"));
    assert_eq!(body["jwks_uri"], format!("{ISSUER}/oauth2/jwks.json"));
    assert_eq!(body["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(body["response_types_supported"], json!(["code"]));
    assert_eq!(
        body["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(body["resource_indicators_supported"], true);
    // Registration is off in this harness, so it must not be advertised.
    assert!(body["registration_endpoint"].is_null());

    // Scopes are derived from the resource registry, not configured.
    let scopes = body["scopes_supported"].as_array().unwrap();
    assert!(scopes.iter().any(|s| s == "mcp:read"));

    // OIDC is on, so the OpenID document is served with the same body.
    let oidc = body_json(h.get("/.well-known/openid-configuration", None).await).await;
    assert_eq!(oidc["issuer"], ISSUER);
    assert_eq!(oidc["id_token_signing_alg_values_supported"], json!(["ES256"]));
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn jwks_publishes_the_key_that_actually_signed_the_token() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();
    let code = h.authorize_code(&client_id, &session, &pkce).await;

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
    let access = tokens["access_token"].as_str().unwrap().to_string();

    let jwks = body_json(h.get("/oauth2/jwks.json", None).await).await;
    let keys = jwks["keys"].as_array().unwrap();
    assert!(!keys.is_empty(), "JWKS must publish the signing key");

    let kid = decode_header(&access)["kid"].as_str().unwrap().to_string();
    let key = keys
        .iter()
        .find(|k| k["kid"] == kid.as_str())
        .unwrap_or_else(|| panic!("kid {kid} is not published in JWKS"));

    assert_eq!(key["kty"], "EC");
    assert_eq!(key["crv"], "P-256");
    assert_eq!(key["alg"], "ES256");
    // The private half must never appear in the public document.
    assert!(key["d"].is_null());

    // And the published key really verifies the token.
    let decoding = jsonwebtoken::DecodingKey::from_ec_components(
        key["x"].as_str().unwrap(),
        key["y"].as_str().unwrap(),
    )
    .unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[h.resource_uri.as_str()]);
    jsonwebtoken::decode::<serde_json::Value>(&access, &decoding, &validation)
        .expect("the published JWKS key must verify the token it signed");
}

/// Rotation must not invalidate tokens that are still inside their lifetime,
/// so the retired key stays published until its grace window closes.
#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn rotation_keeps_older_tokens_verifiable_until_the_key_is_retired() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();
    let code = h.authorize_code(&client_id, &session, &pkce).await;

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
    let access = tokens["access_token"].as_str().unwrap().to_string();
    let old_kid = decode_header(&access)["kid"].as_str().unwrap().to_string();

    let rotated = h
        .engine
        .rotate_oauth_signing_keys(
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(3600),
        )
        .await
        .unwrap();
    assert!(rotated, "an active key should have been rotated");

    let jwks = body_json(h.get("/oauth2/jwks.json", None).await).await;
    let kids: Vec<String> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap().to_string())
        .collect();
    assert!(
        kids.contains(&old_kid),
        "the retired key must stay published while tokens it signed are alive"
    );
    assert!(kids.len() >= 2, "the new key must be published alongside it");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn introspection_answers_the_owning_service_and_nobody_else() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();
    let code = h.authorize_code(&client_id, &session, &pkce).await;

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
    let access = tokens["access_token"].as_str().unwrap().to_string();

    let body = body_json(h.introspect(&access, &h.service_token).await).await;
    assert_eq!(body["active"], true);
    assert_eq!(body["aud"], h.resource_uri);
    assert_eq!(body["client_id"], client_id);
    assert_eq!(body["scope"], "mcp:read");

    // A service token belonging to a service that owns no matching resource
    // gets `active: false`, not someone else's token contents.
    let other = surge_engine::types::ServiceToken::generate();
    h.engine
        .create_service(
            &format!("other-svc-{}", h.suffix),
            other.hash(),
            vec!["introspect".to_string()],
            vec![],
        )
        .await
        .unwrap();
    let body = body_json(h.introspect(&access, other.expose_secret()).await).await;
    assert_eq!(body["active"], false);
    assert!(body["sub"].is_null());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn introspection_requires_the_introspect_grant() {
    let h = harness().await;
    let ungranted = surge_engine::types::ServiceToken::generate();
    h.engine
        .create_service(
            &format!("nogrant-svc-{}", h.suffix),
            ungranted.hash(),
            vec!["identity_read".to_string()],
            vec![],
        )
        .await
        .unwrap();

    let resp = h.introspect("whatever", ungranted.expose_secret()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "unauthorized_client");

    // And an unauthenticated call is refused outright.
    let resp = h
        .post_form("/oauth2/introspect", &[("token", "whatever")])
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn userinfo_answers_only_a_token_carrying_openid() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();

    let uri = h.authorize_uri(
        &client_id,
        &pkce,
        Some(&h.resource_uri),
        Some("mcp:read openid"),
    );
    let target = location(&h.get(&uri, Some(&session)).await);
    let code = query_param(&target, "code").unwrap();

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

    // `openid` was requested, so an ID token comes back with it.
    assert!(tokens["id_token"].as_str().is_some());

    let access = tokens["access_token"].as_str().unwrap();
    let body = body_json(h.bearer_get("/oauth2/userinfo", access).await).await;
    assert_eq!(body["sub"], h.identity_id().await.to_string());
    assert_eq!(body["preferred_username"], format!("oauth-user-{}", h.suffix));

    // A garbage token gets a challenge, not an answer.
    let resp = h.bearer_get("/oauth2/userinfo", "not-a-token").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get("www-authenticate").is_some());
}

fn decode_header(token: &str) -> serde_json::Value {
    use base64::Engine as _;

    let header = token.split('.').next().unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
