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
    assert!(
        body["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with("aeg_rt_")
    );

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
async fn openid_only_sign_in_without_resource_issues_a_userinfo_token() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(false).await;
    let pkce = Pkce::generate();

    let mixed = h
        .get(
            &h.authorize_uri(&client_id, &pkce, None, Some("openid mcp:read")),
            Some(&session),
        )
        .await;
    assert_eq!(
        query_param(&location(&mixed), "error").as_deref(),
        Some("invalid_target")
    );

    let auth = h
        .get(
            &h.authorize_uri(&client_id, &pkce, None, Some("openid")),
            Some(&session),
        )
        .await;
    let flow_id = query_param(&location(&auth), "consent_flow").unwrap();
    let path = format!("/v1/oauth/consent/{flow_id}");
    let flow = body_json(h.get(&path, Some(&session)).await).await;
    let approval = h
        .post_json(
            &path,
            serde_json::json!({ "approve": true, "csrf_token": flow["csrf_token"] }),
            Some(&session),
        )
        .await;
    assert_eq!(approval.status(), StatusCode::OK);
    let redirect = body_json(approval).await;
    let code = query_param(redirect["redirect_to"].as_str().unwrap(), "code").unwrap();
    let (status, body) = exchange(&h, &client_id, &code, &pkce).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scope"], "openid");
    let id_token = decode_claims(body["id_token"].as_str().unwrap());
    assert_eq!(id_token["aud"], client_id);
    let access_token = body["access_token"].as_str().unwrap();
    assert_eq!(
        decode_claims(access_token)["aud"],
        surge_engine::oauth::USERINFO_AUDIENCE
    );
    let userinfo = h.bearer_get("/oauth2/userinfo", access_token).await;
    assert_eq!(userinfo.status(), StatusCode::OK);
    assert_eq!(body_json(userinfo).await["sub"], id_token["sub"]);
    let introspection = h.introspect(access_token, &h.service_token).await;
    assert_eq!(introspection.status(), StatusCode::OK);
    assert_eq!(body_json(introspection).await["active"], false);
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

    // The refusal must not have spent the token. Asking for too much is a
    // client-side bug, and burning the grant over it would strand a session
    // that nothing was wrong with.
    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &client_id),
                ("scope", "mcp:read"),
            ],
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a rejected widen must leave the presented refresh token spendable"
    );
    let narrowed = body_json(resp).await;
    assert_eq!(narrowed["scope"], "mcp:read");

    // Narrowing shapes the access token, not the lineage: the successor still
    // carries the grant, so the next refresh can ask for everything again.
    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", narrowed["refresh_token"].as_str().unwrap()),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["scope"], "mcp:read");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_refresh_may_name_only_the_audience_it_was_issued_for() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();
    let code = h.authorize_code(&client_id, &session, &pkce).await;
    let (_, first) = exchange(&h, &client_id, &code, &pkce).await;
    let refresh = first["refresh_token"].as_str().unwrap().to_string();

    for other in ["https://rs.oauth.test/elsewhere", "urn:example:mcp"] {
        let resp = h
            .post_form(
                "/oauth2/token",
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh),
                    ("client_id", &client_id),
                    ("resource", other),
                ],
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{other}");
        assert_eq!(body_json(resp).await["error"], "invalid_target", "{other}");
    }

    // Refused before rotation, like a widened scope: the token survives, and
    // the grant's own audience (in any spelling that canonicalizes to it)
    // is accepted.
    let own = format!("{}/", h.resource_uri);
    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &client_id),
                ("resource", &own),
            ],
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a rejected resource must leave the presented refresh token spendable"
    );
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_repeated_parameter_is_an_oauth_error() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();
    let code = h.authorize_code(&client_id, &session, &pkce).await;

    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", CLIENT_REDIRECT),
                ("client_id", &client_id),
                ("code_verifier", &pkce.verifier),
                ("resource", &h.resource_uri),
                ("resource", "https://rs.oauth.test/elsewhere"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_uncacheable(&resp, "a malformed token request");
    assert_eq!(body_json(resp).await["error"], "invalid_request");

    // Nothing was redeemed: the code is still good for a well-formed request.
    let (status, _) = exchange(&h, &client_id, &code, &pkce).await;
    assert_eq!(status, StatusCode::OK);
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
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{grant} was accepted"
        );
        assert_eq!(body_json(resp).await["error"], "unsupported_grant_type");
    }
}

/// Decodes the claims without verifying — the signature is JWKS's business
/// (see `oauth_keys.rs`); this is about what the claims *say*.
fn assert_uncacheable(resp: &axum::response::Response, what: &str) {
    assert_eq!(resp.headers()["cache-control"], "no-store", "{what}");
    assert_eq!(resp.headers()["pragma"], "no-cache", "{what}");
}

fn basic(client_id: &str, secret: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// RFC 6749 §5.1: token responses, and the other endpoints that carry tokens
/// or token data, MUST be uncacheable — success and error alike.
#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn token_bearing_responses_are_never_cacheable() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();
    let code = h.authorize_code(&client_id, &session, &pkce).await;

    let issued = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", CLIENT_REDIRECT),
                ("client_id", &client_id),
                ("code_verifier", &pkce.verifier),
            ],
        )
        .await;
    assert_eq!(issued.status(), StatusCode::OK);
    assert_uncacheable(&issued, "token success");
    let tokens = body_json(issued).await;
    let access = tokens["access_token"].as_str().unwrap();

    let refused = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_uncacheable(&refused, "token error");

    let introspection = h.introspect(access, &h.service_token).await;
    assert_uncacheable(&introspection, "introspection");
    let userinfo = h.bearer_get("/oauth2/userinfo", access).await;
    assert_uncacheable(&userinfo, "userinfo");
    let revoked = h
        .post_form(
            "/oauth2/revoke",
            &[
                ("token", tokens["refresh_token"].as_str().unwrap()),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    assert_uncacheable(&revoked, "revocation");

    // Public metadata keeps its own caching policy.
    let jwks = h.get("/oauth2/jwks.json", None).await;
    assert_eq!(jwks.headers()["cache-control"], "public, max-age=300");
}

/// RFC 6749 §5.2: a client that authenticated with HTTP Basic and failed MUST
/// get a 401 carrying a `WWW-Authenticate` challenge in that scheme.
#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn failed_basic_client_auth_is_challenged_in_kind() {
    let h = harness().await;
    let (client_id, _secret) = h
        .client_with(false, vec![CLIENT_REDIRECT.to_string()], true)
        .await;
    let refresh = [
        ("grant_type", "refresh_token"),
        ("refresh_token", "aeg_rt_nope"),
    ];

    for endpoint in ["/oauth2/token", "/oauth2/revoke"] {
        let wrong = h
            .post_form_authorized(endpoint, &basic(&client_id, "aeg_cs_wrong"), &refresh)
            .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED, "{endpoint}");
        let challenge = wrong.headers()["www-authenticate"].to_str().unwrap();
        assert!(challenge.starts_with("Basic "), "{endpoint}: {challenge}");
        assert_eq!(body_json(wrong).await["error"], "invalid_client");

        // A Basic header too malformed to name a client is still an attempt.
        let malformed = h
            .post_form_authorized(endpoint, "Basic !!!", &refresh)
            .await;
        assert_eq!(malformed.status(), StatusCode::UNAUTHORIZED, "{endpoint}");
        assert!(
            malformed.headers().contains_key("www-authenticate"),
            "{endpoint}"
        );

        // Credentials in the body: §5.2 makes the challenge optional; none is sent.
        let mut form = refresh.to_vec();
        form.extend([
            ("client_id", client_id.as_str()),
            ("client_secret", "aeg_cs_wrong"),
        ]);
        let body_auth = h.post_form(endpoint, &form).await;
        assert_eq!(body_auth.status(), StatusCode::UNAUTHORIZED, "{endpoint}");
        assert!(
            !body_auth.headers().contains_key("www-authenticate"),
            "{endpoint}"
        );
    }
}

fn decode_claims(token: &str) -> Value {
    use base64::Engine as _;

    let payload = token.split('.').nth(1).expect("not a JWT");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("payload is not base64url");
    serde_json::from_slice(&bytes).expect("payload is not JSON")
}
