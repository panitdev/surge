//! Dynamic client registration and its abuse controls
//! (internal/oauth-as.md §5.3, §11).
//!
//! This endpoint is unauthenticated by specification. Every test here is
//! about a bound on what an anonymous caller can produce with it.

mod oauth_support;

use axum::http::StatusCode;
use oauth_support::*;
use serde_json::json;

async fn dcr_harness() -> Harness {
    harness_with(|mut settings| {
        settings.allow_dynamic_registration = true;
        settings
    })
    .await
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn registration_is_absent_unless_it_is_turned_on() {
    let h = harness().await;

    let resp = h
        .post_json(
            "/oauth2/register",
            json!({ "redirect_uris": ["https://client.example/cb"] }),
            None,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let doc = body_json(h.get("/.well-known/oauth-authorization-server", None).await).await;
    assert!(doc["registration_endpoint"].is_null());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_registered_client_is_untrusted_third_party_and_scope_capped() {
    let h = dcr_harness().await;

    let doc = body_json(h.get("/.well-known/oauth-authorization-server", None).await).await;
    assert_eq!(
        doc["registration_endpoint"],
        format!("{ISSUER}/oauth2/register")
    );

    let resp = h
        .post_json(
            "/oauth2/register",
            json!({
                "client_name": "Some MCP client",
                "redirect_uris": ["http://127.0.0.1:53821/callback"],
                // Asking for a scope no resource defines, alongside one that
                // exists: the invented scope must simply not appear.
                "scope": "mcp:read mcp:root",
            }),
            None,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;

    let client_id = body["client_id"].as_str().unwrap();
    assert!(client_id.starts_with("aeg_cid_"));
    assert_eq!(body["token_endpoint_auth_method"], "none");
    assert!(body["client_secret"].is_null(), "a public client gets no secret");
    assert_eq!(body["scope"], "mcp:read");

    let client = h.engine.get_oauth_client(client_id).await.unwrap();
    assert!(!client.first_party, "a dynamic client is never first-party");
    assert_eq!(client.trust_state, "untrusted");
    assert_eq!(
        client.registration_source,
        surge_engine::oauth::RegistrationSource::Dynamic
    );
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn redirect_uris_must_be_https_or_loopback_http() {
    let h = dcr_harness().await;

    for (uri, ok) in [
        ("https://client.example/cb", true),
        ("http://127.0.0.1:1234/cb", true),
        ("http://[::1]:1234/cb", true),
        // The native-app allowance is loopback only; plain http anywhere else
        // makes the code interceptable on the wire.
        ("http://client.example/cb", false),
        ("https://*.client.example/cb", false),
        ("ftp://client.example/cb", false),
    ] {
        let resp = h
            .post_json(
                "/oauth2/register",
                json!({ "client_name": "c", "redirect_uris": [uri] }),
                None,
            )
            .await;
        if ok {
            assert_eq!(resp.status(), StatusCode::CREATED, "{uri} should register");
        } else {
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri} should not register");
            assert_eq!(body_json(resp).await["error"], "invalid_client_metadata");
        }
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn registration_cannot_ask_to_be_first_party_or_trusted() {
    let h = dcr_harness().await;

    // These are not parameters of the endpoint; passing them must change
    // nothing, rather than being honoured or erroring in a way that suggests
    // they might be.
    let body = body_json(
        h.post_json(
            "/oauth2/register",
            json!({
                "client_name": "Impostor",
                "redirect_uris": ["https://client.example/cb"],
                "first_party": true,
                "trust_state": "trusted",
                "registration_source": "admin",
            }),
            None,
        )
        .await,
    )
    .await;

    let client = h
        .engine
        .get_oauth_client(body["client_id"].as_str().unwrap())
        .await
        .unwrap();
    assert!(!client.first_party);
    assert_eq!(client.trust_state, "untrusted");
    assert_eq!(
        client.registration_source,
        surge_engine::oauth::RegistrationSource::Dynamic
    );
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_dynamically_registered_client_still_faces_a_consent_screen() {
    let h = dcr_harness().await;
    let session = h.sign_in().await;

    let body = body_json(
        h.post_json(
            "/oauth2/register",
            json!({
                "client_name": "Some MCP client",
                "redirect_uris": [CLIENT_REDIRECT],
                "scope": "mcp:read",
            }),
            None,
        )
        .await,
    )
    .await;
    let client_id = body["client_id"].as_str().unwrap().to_string();

    let pkce = Pkce::generate();
    let resp = h
        .get(
            &h.authorize_uri(&client_id, &pkce, Some(&h.resource_uri), Some("mcp:read")),
            Some(&session),
        )
        .await;
    let target = location(&resp);
    assert!(
        target.starts_with(&format!("{AUTH_UI_ORIGIN}/consent?consent_flow=")),
        "DCR without a consent screen would be a silent token dispenser"
    );

    // And the screen is told this name is self-declared.
    let flow_id = query_param(&target, "consent_flow").unwrap();
    let flow = body_json(
        h.get(&format!("/v1/oauth/consent/{flow_id}"), Some(&session))
            .await,
    )
    .await;
    assert_eq!(flow["client"]["dynamically_registered"], true);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn the_sweep_removes_registrations_that_were_never_used() {
    let h = dcr_harness().await;

    let body = body_json(
        h.post_json(
            "/oauth2/register",
            json!({ "client_name": "Abandoned", "redirect_uris": ["https://client.example/cb"] }),
            None,
        )
        .await,
    )
    .await;
    let client_id = body["client_id"].as_str().unwrap().to_string();

    // A zero TTL means "anything created before now", which is what the
    // scheduled sweep does with a 30-day one.
    let removed = h
        .engine
        .gc_unused_dynamic_clients(std::time::Duration::ZERO)
        .await
        .unwrap();
    assert!(removed >= 1);
    assert!(h.engine.get_oauth_client(&client_id).await.is_err());
}
