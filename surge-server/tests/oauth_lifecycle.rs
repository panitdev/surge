//! Lifecycle of a registration after it exists: registrar-authorized PATCH
//! and DELETE by canonical URI, the grants each change ends, the audit trail,
//! and safe reuse of a deleted URI.
//!
//! The policy-change/issuance serialization is tested at the bottom: the
//! locking scheme is documented in `surge_engine::oauth::lifecycle`.

mod oauth_support;

use std::time::Duration;

use axum::http::StatusCode;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use oauth_support::*;
use serde_json::{Value, json};
use surge_engine::audit::AuditActor;
use surge_engine::oauth::{DeleteOutcome, NewOauthClient, RegistrationSource, ResourceManager};
use surge_engine::schema::{audit_log, oauth_refresh_token, oauth_resource_reservation};
use tower::ServiceExt;
use uuid::Uuid;

async fn db() -> AsyncPgConnection {
    AsyncPgConnection::establish(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap()
}

async fn call(
    h: &Harness,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> axum::response::Response {
    call_with(h, method, path, token, body, &[]).await
}

async fn call_with(
    h: &Harness,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> axum::response::Response {
    let mut req = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req
        .body(axum::body::Body::from(
            body.map(|b| b.to_string()).unwrap_or_default(),
        ))
        .unwrap();
    h.app.clone().oneshot(req).await.unwrap()
}

async fn service(h: &Harness, label: &str, grants: &[&str]) -> (Uuid, String) {
    let token = surge_engine::types::ServiceToken::generate();
    let svc = h
        .engine
        .create_service(
            &format!("{label}-{}", h.suffix),
            token.hash(),
            grants.iter().map(|g| g.to_string()).collect(),
            vec![],
        )
        .await
        .unwrap();
    (svc.id, token.expose_secret().to_string())
}

/// A registrar (Platform) service.
async fn registrar(h: &Harness, label: &str) -> (Uuid, String) {
    service(h, label, &["oauth_resource_register"]).await
}

/// `/v1/oauth/resources/<uri encoded as one segment>`.
fn path(uri: &str) -> String {
    format!("/v1/oauth/resources/{}", percent_encode(uri))
}

fn uri(h: &Harness, name: &str) -> String {
    format!("https://{name}.lifecycle.test/mcp-{}", h.suffix)
}

/// Registers a delegated resource as `token` and returns its registration id.
async fn register(h: &Harness, token: &str, uri: &str, scopes: &[&str]) -> Uuid {
    let resp = call(
        h,
        "POST",
        "/v1/oauth/resources",
        token,
        Some(json!({ "resource_uri": uri, "scopes": scopes })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    body_json(resp).await["registration_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

async fn client(h: &Harness, source: RegistrationSource, audiences: Option<Vec<String>>) -> String {
    h.engine
        .create_oauth_client(NewOauthClient {
            client_name: format!("Lifecycle client {}", h.suffix),
            client_uri: None,
            logo_uri: None,
            redirect_uris: vec![CLIENT_REDIRECT.to_string()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            scopes: vec!["mcp:read".into(), "mcp:write".into()],
            confidential: false,
            first_party: false,
            registration_source: source,
            audiences,
        })
        .await
        .unwrap()
        .0
        .client_id
}

/// Drives authorize -> consent -> code, returning the code and its PKCE pair.
async fn code_for(
    h: &Harness,
    client_id: &str,
    session: &str,
    resource: &str,
    scope: &str,
) -> (String, Pkce) {
    let pkce = Pkce::generate();
    let resp = h
        .get(
            &h.authorize_uri(client_id, &pkce, Some(resource), Some(scope)),
            Some(session),
        )
        .await;
    if resp.status() != StatusCode::SEE_OTHER {
        panic!(
            "authorize failed for {client_id}: {} {}",
            resp.status(),
            body_text(resp).await
        );
    }
    let mut target = location(&resp);
    if let Some(flow) = query_param(&target, "consent_flow") {
        let csrf = body_json(
            h.get(&format!("/v1/oauth/consent/{flow}"), Some(session))
                .await,
        )
        .await["csrf_token"]
            .as_str()
            .unwrap()
            .to_string();
        let resp = h
            .post_json(
                &format!("/v1/oauth/consent/{flow}"),
                json!({ "approve": true, "csrf_token": csrf }),
                Some(session),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        target = body_json(resp).await["redirect_to"]
            .as_str()
            .unwrap()
            .to_string();
    }
    let code = query_param(&target, "code").unwrap_or_else(|| panic!("no code: {target}"));
    (code, pkce)
}

async fn redeem(h: &Harness, client_id: &str, code: &str, pkce: &Pkce) -> (StatusCode, Value) {
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
    (resp.status(), body_json(resp).await)
}

/// A full grant: (access token, refresh token).
async fn grant(
    h: &Harness,
    client_id: &str,
    session: &str,
    resource: &str,
    scope: &str,
) -> (String, String) {
    let (code, pkce) = code_for(h, client_id, session, resource, scope).await;
    let (status, tokens) = redeem(h, client_id, &code, &pkce).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    (
        tokens["access_token"].as_str().unwrap().to_string(),
        tokens["refresh_token"].as_str().unwrap().to_string(),
    )
}

async fn refresh(h: &Harness, client_id: &str, token: &str) -> (StatusCode, Value) {
    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", token),
                ("client_id", client_id),
            ],
        )
        .await;
    (resp.status(), body_json(resp).await)
}

async fn patch(h: &Harness, token: &str, uri: &str, body: Value) -> axum::response::Response {
    call(h, "PATCH", &path(uri), token, Some(body)).await
}

async fn consent_scopes(h: &Harness, client_id: &str, reg: Uuid) -> Option<Vec<String>> {
    h.engine
        .find_consent(client_id, h.identity_id().await, reg)
        .await
        .unwrap()
        .map(|c| c.scopes)
}

async fn live_tokens(reg: Uuid) -> i64 {
    oauth_refresh_token::table
        .filter(oauth_refresh_token::registration_id.eq(reg))
        .filter(oauth_refresh_token::revoked_at.is_null())
        .count()
        .get_result(&mut db().await)
        .await
        .unwrap()
}

// -- routing ---------------------------------------------------------------

/// A harness with the global DCR switch on, which dynamically registered
/// clients need to be eligible for anything.
async fn dcr_harness() -> Harness {
    harness_with(|mut settings| {
        settings.allow_dynamic_registration = true;
        settings
    })
    .await
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn encoded_paths_and_queries_route_to_the_canonical_uri() {
    let h = harness().await;
    let (_, token) = registrar(&h, "routing").await;
    let plain = uri(&h, "plain");
    let id = register(&h, &token, &plain, &["mcp:read"]).await;

    // The URI is one percent-encoded path segment.
    let resp = patch(&h, &token, &plain, json!({ "scope_descriptions": { "mcp:read": "a" } })).await;
    assert_eq!(resp.status(), StatusCode::OK);
    // A trailing slash canonicalizes away.
    let resp = call(
        &h,
        "PATCH",
        &format!("{}%2F", path(&plain)),
        &token,
        Some(json!({ "scope_descriptions": { "mcp:read": "b" } })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "trailing slash canonicalizes");

    // Unencoded slashes are separate segments: no such route.
    let resp = call(
        &h,
        "PATCH",
        &format!("/v1/oauth/resources/{plain}"),
        &token,
        Some(json!({ "dcr_enabled": true })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // A query component inside the URI is encoded into the segment and
    // refused as an audience; it is not mistaken for the request's query.
    let resp = call(
        &h,
        "DELETE",
        &format!("{}%3Fx%3D1?registration_id={id}", path(&plain)),
        &token,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let resp = call(
        &h,
        "DELETE",
        &format!("{}%23frag?registration_id={id}", path(&plain)),
        &token,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // An encoded path component inside the URI survives: %2F within the URI's
    // own path is double-encoded and is a different audience from `a/b`.
    let odd = format!("https://odd.lifecycle.test:8443/a%2Fb-{}", h.suffix);
    let odd_id = register(&h, &token, &odd, &["mcp:read"]).await;
    assert!(percent_encode(&odd).contains("%252F"));
    let resp = patch(&h, &token, &odd, json!({ "scope_descriptions": {} })).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = call(
        &h,
        "GET",
        &path(&odd),
        &token,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["registration_id"], odd_id.to_string());
    let plain_slash = odd.replace("%2F", "/");
    let resp = call(&h, "GET", &path(&plain_slash), &token, None).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "a/b is another audience");

    // The registration id rides the real query string, or If-Match.
    let resp = call(&h, "DELETE", &path(&odd), &token, None).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a registrar must say which registration"
    );
    let resp = call(
        &h,
        "DELETE",
        &format!("{}?registration_id={odd_id}", path(&odd)),
        &token,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = call_with(
        &h,
        "DELETE",
        &path(&plain),
        &token,
        None,
        &[("if-match", &format!("\"{id}\""))],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // A registration id is not a lifecycle address.
    let resp = call(&h, "PATCH", &format!("/v1/oauth/resources/{id}"), &token, Some(json!({"dcr_enabled": true}))).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // Disagreeing preconditions are refused.
    let resp = call_with(
        &h,
        "DELETE",
        &format!("{}?registration_id={id}", path(&plain)),
        &token,
        None,
        &[("if-match", &Uuid::now_v7().to_string())],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_registrar_manages_only_its_own_registrations() {
    let h = harness().await;
    let (_, mine) = registrar(&h, "mine").await;
    let (_, theirs) = registrar(&h, "theirs").await;
    let (_, nobody) = service(&h, "nogrant", &["introspect"]).await;
    let owned = uri(&h, "owned");
    let id = register(&h, &mine, &owned, &["mcp:read", "mcp:write"]).await;

    for (token, expected) in [
        (&theirs, StatusCode::NOT_FOUND),
        (&nobody, StatusCode::FORBIDDEN),
    ] {
        let resp = patch(&h, token, &owned, json!({ "scopes": ["mcp:read"] })).await;
        assert_eq!(resp.status(), expected);
        let resp = call(
            &h,
            "DELETE",
            &format!("{}?registration_id={id}", path(&owned)),
            token,
            None,
        )
        .await;
        assert_eq!(resp.status(), expected);
    }
    // Neither changed anything.
    assert_eq!(
        h.engine.get_oauth_resource(&owned).await.unwrap().scopes,
        vec!["mcp:read", "mcp:write"]
    );

    // A registrar cannot touch an administrator's service registration.
    let resp = patch(&h, &mine, &h.resource_uri, json!({ "scopes": ["mcp:read"] })).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // The owner can; so can an administrator (including a legacy
    // registration with an unknown registrar).
    let resp = patch(&h, &mine, &owned, json!({ "scopes": ["mcp:read"] })).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = patch(&h, &h.service_token, &h.resource_uri, json!({ "scopes": ["mcp:read", "mcp:write"] })).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Validation.
    for bad in [
        json!({}),
        json!({ "scopes": [] }),
        json!({ "scopes": ["has space"] }),
        json!({ "scopes": ["openid"] }),
        json!({ "allowed_cimd_client_ids": ["http://insecure.example/c.json"] }),
        json!({ "allowed_cimd_client_ids": ["https://a.example/"] }),
        json!({ "allowed_cimd_client_ids": ["https://u:p@a.example/c.json"] }),
        json!({ "allowed_cimd_client_ids": ["https://a.example/c.json#f"] }),
        json!({ "scope_descriptions": ["x"] }),
        json!({ "owner_service_id": Uuid::now_v7() }),
    ] {
        let resp = patch(&h, &mine, &owned, bad.clone()).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    // DCR opt-in is for delegated registrations.
    let resp = patch(&h, &h.service_token, &h.resource_uri, json!({ "dcr_enabled": true })).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// -- PATCH invalidation ----------------------------------------------------

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn scope_removal_trims_consents_and_ends_affected_families() {
    let h = harness().await;
    let session = h.sign_in().await;
    let (_, token) = registrar(&h, "scopes").await;
    let rs = uri(&h, "scopes");
    let other = uri(&h, "scopes-other");
    let reg = register(&h, &token, &rs, &["mcp:read", "mcp:write"]).await;
    let other_reg = register(&h, &token, &other, &["mcp:read", "mcp:write"]).await;

    let both = client(&h, RegistrationSource::Admin, Some(vec![rs.clone(), other.clone()])).await;
    let read_only = client(&h, RegistrationSource::Admin, Some(vec![rs.clone()])).await;
    let write_only = client(&h, RegistrationSource::Admin, Some(vec![rs.clone()])).await;

    let (both_access, both_refresh) = grant(&h, &both, &session, &rs, "mcp:read mcp:write").await;
    let (_, read_refresh) = grant(&h, &read_only, &session, &rs, "mcp:read").await;
    let (_, write_refresh) = grant(&h, &write_only, &session, &rs, "mcp:write").await;
    let (_, other_refresh) = grant(&h, &both, &session, &other, "mcp:read mcp:write").await;
    let _ = both_access;

    // Outstanding, unredeemed: a code and a pending consent flow carrying
    // the scope about to go.
    let (stale_code, stale_pkce) = code_for(&h, &both, &session, &rs, "mcp:write").await;
    let pkce = Pkce::generate();
    let resp = h
        .get(
            &h.authorize_uri(&write_only, &pkce, Some(&rs), Some("mcp:read mcp:write")),
            Some(&session),
        )
        .await;
    let flow = query_param(&location(&resp), "consent_flow").expect("a new scope needs consent");

    let resp = patch(&h, &token, &rs, json!({ "scopes": ["mcp:read"] })).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let updated = body_json(resp).await;
    assert_eq!(updated["scopes"], json!(["mcp:read"]));

    // Affected families are revoked; the one that never carried it is not.
    assert_eq!(refresh(&h, &both, &both_refresh).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(refresh(&h, &write_only, &write_refresh).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(refresh(&h, &read_only, &read_refresh).await.0, StatusCode::OK);
    // Consents: trimmed, trimmed to nothing and deleted, untouched.
    assert_eq!(consent_scopes(&h, &both, reg).await, Some(vec!["mcp:read".to_string()]));
    assert_eq!(consent_scopes(&h, &write_only, reg).await, None);
    assert_eq!(consent_scopes(&h, &read_only, reg).await, Some(vec!["mcp:read".to_string()]));
    // The other audience is unaffected, though it shares the scope names.
    assert_eq!(refresh(&h, &both, &other_refresh).await.0, StatusCode::OK);
    assert!(live_tokens(other_reg).await >= 1);

    // The unredeemed code and the pending flow died with the scope.
    let (status, _) = redeem(&h, &both, &stale_code, &stale_pkce).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let resp = h.get(&format!("/v1/oauth/consent/{flow}"), Some(&session)).await;
    assert_ne!(resp.status(), StatusCode::OK);

    // Asking for the scope that is gone is refused; and adding it back
    // restores the *offer*, not the old grants.
    let pkce = Pkce::generate();
    let resp = h
        .get(&h.authorize_uri(&both, &pkce, Some(&rs), Some("mcp:write")), Some(&session))
        .await;
    assert_eq!(query_param(&location(&resp), "error").as_deref(), Some("invalid_scope"));
    patch(&h, &token, &rs, json!({ "scopes": ["mcp:read", "mcp:write"] })).await;
    assert_eq!(refresh(&h, &both, &both_refresh).await.0, StatusCode::BAD_REQUEST);
    let pkce = Pkce::generate();
    let resp = h
        .get(&h.authorize_uri(&both, &pkce, Some(&rs), Some("mcp:write")), Some(&session))
        .await;
    assert!(
        query_param(&location(&resp), "consent_flow").is_some(),
        "the trimmed consent no longer covers write: a fresh approval is needed"
    );
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn scope_removal_makes_introspection_inactive() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = h.client(true).await;
    let pkce = Pkce::generate();
    let code = h.authorize_code(&client_id, &session, &pkce).await;
    let (status, tokens) = redeem(&h, &client_id, &code, &pkce).await;
    assert_eq!(status, StatusCode::OK);
    let access = tokens["access_token"].as_str().unwrap();
    let live = body_json(h.introspect(access, &h.service_token).await).await;
    assert_eq!(live["active"], true);

    // `mcp:read` is what the token carries; removing it ends the family.
    let resp = patch(&h, &h.service_token, &h.resource_uri, json!({ "scopes": ["mcp:write"] })).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let after = body_json(h.introspect(access, &h.service_token).await).await;
    assert_eq!(after["active"], false);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn description_only_edits_preserve_every_grant() {
    let h = harness().await;
    let session = h.sign_in().await;
    let (_, token) = registrar(&h, "desc").await;
    let rs = uri(&h, "desc");
    let reg = register(&h, &token, &rs, &["mcp:read", "mcp:write"]).await;
    let c = client(&h, RegistrationSource::Admin, Some(vec![rs.clone()])).await;
    let (_, refresh_token) = grant(&h, &c, &session, &rs, "mcp:read mcp:write").await;
    let (code, pkce) = code_for(&h, &c, &session, &rs, "mcp:read").await;

    let resp = patch(
        &h,
        &token,
        &rs,
        json!({ "scope_descriptions": { "mcp:read": "Read it all" } }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["scope_descriptions"]["mcp:read"], "Read it all");

    assert_eq!(live_tokens(reg).await, 1);
    assert_eq!(
        consent_scopes(&h, &c, reg).await,
        Some(vec!["mcp:read".to_string(), "mcp:write".to_string()])
    );
    assert_eq!(redeem(&h, &c, &code, &pkce).await.0, StatusCode::OK);
    assert_eq!(refresh(&h, &c, &refresh_token).await.0, StatusCode::OK);
    // A patch that changes nothing is not an event.
    let before: i64 = audit_log::table
        .filter(audit_log::action.eq("update_oauth_resource"))
        .filter(audit_log::subject.contains(json!({ "registration_id": reg })))
        .count()
        .get_result(&mut db().await)
        .await
        .unwrap();
    let resp = patch(&h, &token, &rs, json!({ "scope_descriptions": { "mcp:read": "Read it all" } })).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let after: i64 = audit_log::table
        .filter(audit_log::action.eq("update_oauth_resource"))
        .filter(audit_log::subject.contains(json!({ "registration_id": reg })))
        .count()
        .get_result(&mut db().await)
        .await
        .unwrap();
    assert_eq!(before, after);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn removing_a_cimd_client_ends_its_grants_and_restoring_it_needs_fresh_consent() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    let session = h.sign_in().await;
    let (_, token) = registrar(&h, "cimd").await;
    let rs = uri(&h, "cimd");
    let reg = register(&h, &token, &rs, &["mcp:read"]).await;
    let cimd = format!("https://app.lifecycle.test/client-{}.json", h.suffix);
    docs.publish_default(&cimd);
    let bystander = client(&h, RegistrationSource::Admin, Some(vec![rs.clone()])).await;

    let resp = patch(&h, &token, &rs, json!({ "allowed_cimd_client_ids": [cimd, cimd] })).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["allowed_cimd_client_ids"], json!([cimd]));

    let (_, cimd_refresh) = grant(&h, &cimd, &session, &rs, "mcp:read").await;
    let (_, bystander_refresh) = grant(&h, &bystander, &session, &rs, "mcp:read").await;
    // Outstanding: an unredeemed code, and a pending consent flow after the
    // consent is gone is exercised below.
    let (code, pkce) = code_for(&h, &cimd, &session, &rs, "mcp:read").await;

    let resp = patch(&h, &token, &rs, json!({ "allowed_cimd_client_ids": [] })).await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(refresh(&h, &cimd, &cimd_refresh).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(redeem(&h, &cimd, &code, &pkce).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(consent_scopes(&h, &cimd, reg).await, None);
    // Others on the same registration are untouched.
    assert_eq!(refresh(&h, &bystander, &bystander_refresh).await.0, StatusCode::OK);
    // Not eligible now.
    let pkce2 = Pkce::generate();
    let resp = h
        .get(&h.authorize_uri(&cimd, &pkce2, Some(&rs), Some("mcp:read")), Some(&session))
        .await;
    // No allowlist entry, so no document is fetched and nothing is trusted
    // enough to redirect to: an error page.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_text(resp).await.contains("invalid_target"));

    // Restoring eligibility restores nothing: the old refresh token stays
    // dead and the user is asked again.
    patch(&h, &token, &rs, json!({ "allowed_cimd_client_ids": [cimd] })).await;
    assert_eq!(refresh(&h, &cimd, &cimd_refresh).await.0, StatusCode::BAD_REQUEST);
    let resp = h
        .get(&h.authorize_uri(&cimd, &pkce2, Some(&rs), Some("mcp:read")), Some(&session))
        .await;
    assert!(query_param(&location(&resp), "consent_flow").is_some());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn closing_open_cimd_uses_the_new_list_and_preserves_other_grants() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    let session = h.sign_in().await;
    let (_, token) = registrar(&h, "open-cimd").await;
    let (_, foreign) = registrar(&h, "foreign-cimd").await;
    let rs = uri(&h, "open-cimd");
    let created = call(
        &h,
        "POST",
        "/v1/oauth/resources",
        &token,
        Some(json!({
            "resource_uri": rs, "scopes": ["mcp:read", "mcp:write"], "cimd_open": true,
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = body_json(created).await;
    assert_eq!(created["cimd_open"], true);
    let reg = created["registration_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let list = body_json(call(&h, "GET", "/v1/oauth/resources", &token, None).await).await;
    assert_eq!(list["resources"][0]["cimd_open"], true);
    let read = body_json(call(&h, "GET", &path(&rs), &token, None).await).await;
    assert_eq!(read["cimd_open"], true);
    assert_eq!(
        patch(&h, &foreign, &rs, json!({ "cimd_open": false }))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    let excluded = format!("https://excluded.lifecycle.test/{}.json", h.suffix);
    let retained = format!("https://retained.lifecycle.test/{}.json", h.suffix);
    docs.publish_default(&excluded);
    docs.publish_default(&retained);
    let bystander = client(&h, RegistrationSource::Admin, Some(vec![rs.clone()])).await;
    let (_, excluded_refresh) = grant(&h, &excluded, &session, &rs, "mcp:read").await;
    let (_, retained_refresh) = grant(&h, &retained, &session, &rs, "mcp:read").await;
    let (_, bystander_refresh) = grant(&h, &bystander, &session, &rs, "mcp:read").await;
    let (code, pkce) = code_for(&h, &excluded, &session, &rs, "mcp:read").await;

    // While open, list edits leave even an excluded client's consent intact.
    assert_eq!(
        patch(
            &h,
            &token,
            &rs,
            json!({ "allowed_cimd_client_ids": [&excluded] })
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        patch(&h, &token, &rs, json!({ "allowed_cimd_client_ids": [] }))
            .await
            .status(),
        StatusCode::OK
    );
    assert!(consent_scopes(&h, &excluded, reg).await.is_some());
    let browser = h.engine.create_chooser_browser().await.unwrap();
    let request_id = h
        .engine
        .save_chooser_request(
            &surge_engine::oauth::ChooserCredential::Browser(browser.token),
            reg,
            json!({ "client_id": excluded }),
        )
        .await
        .unwrap();
    let pending = h
        .get(
            &h.authorize_uri(&excluded, &Pkce::generate(), Some(&rs), Some("mcp:write")),
            Some(&session),
        )
        .await;
    let pending = query_param(&location(&pending), "consent_flow").unwrap();
    let pending_path = format!("/v1/oauth/consent/{pending}");
    assert_eq!(
        h.get(&pending_path, Some(&session)).await.status(),
        StatusCode::OK
    );

    let closed = patch(
        &h,
        &token,
        &rs,
        json!({
            "cimd_open": false, "allowed_cimd_client_ids": [&retained],
        }),
    )
    .await;
    assert_eq!(closed.status(), StatusCode::OK);
    let closed = body_json(closed).await;
    assert_eq!(closed["cimd_open"], false);
    assert_eq!(closed["allowed_cimd_client_ids"], json!([retained]));
    assert_eq!(consent_scopes(&h, &excluded, reg).await, None);
    use surge_engine::schema::oauth_authorization_request;
    assert_eq!(
        oauth_authorization_request::table
            .find(request_id)
            .count()
            .get_result::<i64>(&mut db().await)
            .await
            .unwrap(),
        0
    );
    assert_ne!(
        h.get(&pending_path, Some(&session)).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        redeem(&h, &excluded, &code, &pkce).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        refresh(&h, &excluded, &excluded_refresh).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        refresh(&h, &retained, &retained_refresh).await.0,
        StatusCode::OK
    );
    assert_eq!(
        refresh(&h, &bystander, &bystander_refresh).await.0,
        StatusCode::OK
    );

    let reopened = patch(&h, &token, &rs, json!({ "cimd_open": true })).await;
    assert_eq!(reopened.status(), StatusCode::OK);
    assert_eq!(
        body_json(reopened).await["allowed_cimd_client_ids"],
        json!([retained])
    );
    assert_eq!(
        refresh(&h, &excluded, &excluded_refresh).await.0,
        StatusCode::BAD_REQUEST
    );

    let details: Vec<Option<Value>> = audit_log::table
        .filter(audit_log::action.eq("update_oauth_resource"))
        .filter(audit_log::subject.contains(json!({ "registration_id": reg })))
        .select(audit_log::detail)
        .load(&mut db().await)
        .await
        .unwrap();
    assert!(details.into_iter().flatten().any(|detail| {
        detail["cimd_open"] == json!({ "from": true, "to": false })
            && detail["invalidated"]["flows_removed"].as_u64().unwrap_or(0) >= 1
            && detail["invalidated"]["requests_removed"] == 1
    }));
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn disabling_dcr_ends_dynamic_client_grants_flows_and_codes() {
    let h = dcr_harness().await;
    let session = h.sign_in().await;
    let (_, token) = registrar(&h, "dcr").await;
    let rs = uri(&h, "dcr");
    let reg = register(&h, &token, &rs, &["mcp:read"]).await;
    let description = "<b>Developer-authored description</b>";
    let resp = patch(
        &h,
        &token,
        &rs,
        json!({
            "dcr_enabled": true,
            "scope_descriptions": { "mcp:read": description },
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["dcr_enabled"], true);

    let dynamic = client(&h, RegistrationSource::Dynamic, None).await;
    let bound = client(&h, RegistrationSource::Admin, Some(vec![rs.clone()])).await;
    let (_, dyn_refresh) = grant(&h, &dynamic, &session, &rs, "mcp:read").await;
    let (_, bound_refresh) = grant(&h, &bound, &session, &rs, "mcp:read").await;
    let (code, pkce) = code_for(&h, &dynamic, &session, &rs, "mcp:read").await;
    // A pending consent flow: a second scope the consent does not cover.
    let pending = {
        let pkce = Pkce::generate();
        let resp = h
            .get(&h.authorize_uri(&dynamic, &pkce, Some(&rs), Some("mcp:read")), Some(&session))
            .await;
        // Consent already stands, so this goes straight to a code; make a
        // flow with a different client instead.
        let _ = resp;
        let fresh = client(&h, RegistrationSource::Dynamic, None).await;
        let resp = h
            .get(&h.authorize_uri(&fresh, &pkce, Some(&rs), Some("mcp:read")), Some(&session))
            .await;
        query_param(&location(&resp), "consent_flow").expect("consent flow")
    };

    let view = h.get(&format!("/v1/oauth/consent/{pending}"), Some(&session)).await;
    assert_eq!(view.status(), StatusCode::OK);
    let view = body_json(view).await;
    assert_eq!(view["resource"]["registration_source"], "delegated");
    assert_eq!(view["scopes"][0]["description"], description);

    let resp = patch(&h, &token, &rs, json!({ "dcr_enabled": false })).await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(refresh(&h, &dynamic, &dyn_refresh).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(redeem(&h, &dynamic, &code, &pkce).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(consent_scopes(&h, &dynamic, reg).await, None);
    let resp = h.get(&format!("/v1/oauth/consent/{pending}"), Some(&session)).await;
    assert_ne!(resp.status(), StatusCode::OK, "the pending flow was removed");
    // An explicitly bound client of another kind is still eligible.
    assert_eq!(refresh(&h, &bound, &bound_refresh).await.0, StatusCode::OK);

    // Re-enabling does not bring the dynamic client's grants back.
    patch(&h, &token, &rs, json!({ "dcr_enabled": true })).await;
    assert_eq!(refresh(&h, &dynamic, &dyn_refresh).await.0, StatusCode::BAD_REQUEST);
    let pkce = Pkce::generate();
    let resp = h
        .get(&h.authorize_uri(&dynamic, &pkce, Some(&rs), Some("mcp:read")), Some(&session))
        .await;
    assert!(query_param(&location(&resp), "consent_flow").is_some());
}

// -- DELETE ----------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn deletion_ends_every_grant_and_reserves_the_uri() {
    let h = harness().await;
    let session = h.sign_in().await;
    let (registrar_id, token) = registrar(&h, "del").await;
    let doomed = uri(&h, "doomed");
    let survivor = uri(&h, "survivor");
    let id = register(&h, &token, &doomed, &["mcp:read"]).await;
    register(&h, &token, &survivor, &["mcp:read"]).await;
    let c = client(&h, RegistrationSource::Admin, Some(vec![doomed.clone(), survivor.clone()])).await;
    let (_, doomed_refresh) = grant(&h, &c, &session, &doomed, "mcp:read").await;
    let (_, survivor_refresh) = grant(&h, &c, &session, &survivor, "mcp:read").await;
    let (code, pkce) = code_for(&h, &c, &session, &doomed, "mcp:read").await;

    let delete = format!("{}?registration_id={id}", path(&doomed));
    assert_eq!(
        call(&h, "DELETE", &delete, &token, None).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(live_tokens(id).await, 0);
    assert_eq!(refresh(&h, &c, &doomed_refresh).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(redeem(&h, &c, &code, &pkce).await.0, StatusCode::BAD_REQUEST);
    // Other audiences continue working.
    assert_eq!(refresh(&h, &c, &survivor_refresh).await.0, StatusCode::OK);

    // The URI is reserved until the access-token lifetime plus skew.
    let reserved_until: chrono::DateTime<chrono::Utc> = oauth_resource_reservation::table
        .find(&doomed)
        .select(oauth_resource_reservation::reserved_until)
        .first(&mut db().await)
        .await
        .unwrap();
    let remaining = (reserved_until - chrono::Utc::now()).num_seconds();
    // At least the configured lifetime; another test may have raised the
    // recorded high-water mark on this database.
    assert!(remaining >= 600, "{remaining}");
    for token in [&token, &h.service_token] {
        let resp = call(
            &h,
            "POST",
            "/v1/oauth/resources",
            token,
            Some(json!({ "resource_uri": doomed, "scopes": ["mcp:read"] })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(resp).await["error"], "resource_reserved");
    }
    assert_eq!(h.engine.get_oauth_resource(&doomed).await.err().map(|_| ()), Some(()));

    // A retry of the same delete is a no-op.
    assert_eq!(
        call(&h, "DELETE", &delete, &token, None).await.status(),
        StatusCode::NO_CONTENT
    );
    // Another registrar's retry learns nothing.
    let (_, other) = registrar(&h, "del-other").await;
    assert_eq!(
        call(&h, "DELETE", &delete, &other, None).await.status(),
        StatusCode::NOT_FOUND
    );

    // The waiting period passes and someone registers the URI again.
    diesel::update(oauth_resource_reservation::table.find(&doomed))
        .set(oauth_resource_reservation::reserved_until.eq(chrono::Utc::now() - chrono::Duration::seconds(1)))
        .execute(&mut db().await)
        .await
        .unwrap();
    let successor = register(&h, &token, &doomed, &["mcp:read"]).await;
    assert_ne!(successor, id);
    // The approval for the old registration does not carry over.
    assert_eq!(
        h.engine.get_oauth_client(&c).await.unwrap().audiences.unwrap(),
        vec![survivor.clone()]
    );

    // A late retry of the original delete cannot take the successor down.
    let resp = call(&h, "DELETE", &delete, &token, None).await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    assert!(h.engine.get_oauth_resource(&doomed).await.is_ok());
    // Nor can one that names no registration at all, for a registrar.
    let resp = call(&h, "DELETE", &path(&doomed), &token, None).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(h.engine.get_oauth_resource(&doomed).await.is_ok());
    // PATCH honors the same precondition.
    let resp = call(
        &h,
        "PATCH",
        &format!("{}?registration_id={id}", path(&doomed)),
        &token,
        Some(json!({ "dcr_enabled": true })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);

    // Audit: create, update and delete carry the actor and the registration.
    let rows: Vec<(String, Value, Value, Option<Value>)> = audit_log::table
        .filter(audit_log::subject.contains(json!({ "registration_id": id })))
        .order(audit_log::id.asc())
        .select((audit_log::action, audit_log::actor, audit_log::subject, audit_log::detail))
        .load(&mut db().await)
        .await
        .unwrap();
    let actions: Vec<_> = rows.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(actions, ["create_oauth_resource", "delete_oauth_resource"]);
    for (_, actor, subject, _) in &rows {
        assert_eq!(actor["type"], "service");
        assert_eq!(actor["id"], registrar_id.to_string());
        assert_eq!(subject["resource_uri"], doomed);
        assert_eq!(subject["registrar_service_id"], registrar_id.to_string());
    }
    assert!(rows[1].3.as_ref().unwrap()["reserved_until"].is_string());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn updates_are_audited_and_the_cli_deletes_through_the_same_logic() {
    let h = harness().await;
    let session = h.sign_in().await;
    let (registrar_id, token) = registrar(&h, "audit").await;
    let rs = uri(&h, "audit");
    let id = register(&h, &token, &rs, &["mcp:read", "mcp:write"]).await;
    let c = client(&h, RegistrationSource::Admin, Some(vec![rs.clone()])).await;
    let (_, refresh_token) = grant(&h, &c, &session, &rs, "mcp:read mcp:write").await;

    patch(&h, &token, &rs, json!({ "scopes": ["mcp:read"], "dcr_enabled": true })).await;
    let (actor, subject, detail): (Value, Value, Option<Value>) = audit_log::table
        .filter(audit_log::action.eq("update_oauth_resource"))
        .filter(audit_log::subject.contains(json!({ "registration_id": id })))
        .select((audit_log::actor, audit_log::subject, audit_log::detail))
        .first(&mut db().await)
        .await
        .unwrap();
    assert_eq!(actor["id"], registrar_id.to_string());
    assert_eq!(subject["registration_id"], id.to_string());
    let detail = detail.unwrap();
    assert_eq!(detail["scopes_removed"], json!(["mcp:write"]));
    assert_eq!(detail["dcr_enabled"], json!({ "from": false, "to": true }));
    assert_eq!(detail["invalidated"]["refresh_tokens_revoked"], 1);
    assert_eq!(refresh(&h, &c, &refresh_token).await.0, StatusCode::BAD_REQUEST);

    // The operator CLI: same lifecycle (grants ended, URI reserved, audited
    // with the operator as actor), no registrar restriction.
    let (_, live_refresh) = grant(&h, &c, &session, &rs, "mcp:read").await;
    surge_server::cli::oauth(
        surge_server::cli::OauthCommand::Resource(surge_server::cli::ResourceCommand::Delete {
            uri: rs.clone(),
            registration_id: Some(id),
        }),
        h.engine.clone(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(refresh(&h, &c, &live_refresh).await.0, StatusCode::BAD_REQUEST);
    assert!(
        oauth_resource_reservation::table
            .find(&rs)
            .count()
            .get_result::<i64>(&mut db().await)
            .await
            .unwrap()
            == 1
    );
    let (actor, detail): (Value, Option<Value>) = audit_log::table
        .filter(audit_log::action.eq("delete_oauth_resource"))
        .filter(audit_log::subject.contains(json!({ "registration_id": id })))
        .select((audit_log::actor, audit_log::detail))
        .first(&mut db().await)
        .await
        .unwrap();
    assert_eq!(actor["type"], "operator");
    assert_eq!(detail.unwrap()["ended"]["live_refresh_tokens"], 1);

    // And the operator's create is audited too.
    let owner = h.engine.get_oauth_resource(&h.resource_uri).await.unwrap().service_id.unwrap();
    let cli_uri = uri(&h, "cli");
    let created = h
        .engine
        .create_oauth_resource_as(
            AuditActor::Operator { name: "op".into() },
            &cli_uri,
            owner,
            vec!["mcp:read".into()],
            json!({}),
        )
        .await
        .unwrap();
    let actor: Value = audit_log::table
        .filter(audit_log::action.eq("create_oauth_resource"))
        .filter(audit_log::subject.contains(json!({ "registration_id": created.registration_id })))
        .select(audit_log::actor)
        .first(&mut db().await)
        .await
        .unwrap();
    assert_eq!(actor["name"], "op");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn an_administrator_deletes_a_legacy_service_registration() {
    let h = harness().await;
    let owner = h.engine.get_oauth_resource(&h.resource_uri).await.unwrap().service_id.unwrap();
    let legacy = uri(&h, "legacy");
    let created = h
        .engine
        .create_oauth_resource(&legacy, owner, vec!["mcp:read".into()], json!({}))
        .await
        .unwrap();
    // A registrar cannot; the administrator can, with or without a precondition.
    let (_, token) = registrar(&h, "legacy").await;
    let resp = call(
        &h,
        "DELETE",
        &format!("{}?registration_id={}", path(&legacy), created.registration_id),
        &token,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = call(&h, "DELETE", &path(&legacy), &h.service_token, None).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(h.engine.get_oauth_resource(&legacy).await.is_err());
}

// -- serialization with issuance ------------------------------------------

/// Takes the registration lock a policy change takes, in a transaction the
/// test holds open: stands in for a policy change that is mid-flight.
async fn hold_policy_lock(reg: Uuid) -> AsyncPgConnection {
    let mut conn = db().await;
    diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
    diesel::sql_query("SELECT 1 FROM surge.oauth_resource WHERE id = $1 FOR UPDATE")
        .bind::<diesel::sql_types::Uuid, _>(reg)
        .execute(&mut conn)
        .await
        .unwrap();
    conn
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn issuance_waits_for_a_policy_change_and_is_judged_by_it() {
    let h = harness().await;
    let session = h.sign_in().await;
    let (_, token) = registrar(&h, "wait").await;
    let rs = uri(&h, "wait");
    let reg = register(&h, &token, &rs, &["mcp:read", "mcp:write"]).await;
    let c = client(&h, RegistrationSource::Admin, Some(vec![rs.clone()])).await;
    let (_, refresh_token) = grant(&h, &c, &session, &rs, "mcp:read mcp:write").await;
    let (code, pkce) = code_for(&h, &c, &session, &rs, "mcp:read mcp:write").await;

    // A policy change is mid-flight (it holds the registration)...
    let mut change = hold_policy_lock(reg).await;
    let h = std::sync::Arc::new(h);
    let rotating = {
        let (h, c, r) = (h.clone(), c.clone(), refresh_token.clone());
        tokio::spawn(async move { refresh(&h, &c, &r).await })
    };
    let redeeming = {
        let (h, c) = (h.clone(), c.clone());
        tokio::spawn(async move { redeem(&h, &c, &code, &pkce).await })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    // ...so refresh and code redemption have not been allowed past it.
    assert!(!rotating.is_finished(), "a refresh ran through a policy change");
    assert!(!redeeming.is_finished(), "a redemption ran through a policy change");

    // The change removes the client's eligibility and commits.
    diesel::sql_query(
        "DELETE FROM surge.oauth_client_audience WHERE registration_id = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(reg)
    .execute(&mut change)
    .await
    .unwrap();
    diesel::sql_query("COMMIT").execute(&mut change).await.unwrap();

    // Both resume and are judged by the new policy, not the old.
    let (status, body) = rotating.await.unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_target");
    let (status, body) = redeeming.await.unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(live_tokens(reg).await, 0);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn cimd_authorization_and_token_writes_recheck_after_a_resource_closes() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    let session = h.sign_in().await;
    let (_, token) = registrar(&h, "cimd-race").await;
    let rs = uri(&h, "cimd-race");
    let reg = register(&h, &token, &rs, &["mcp:read"]).await;
    assert_eq!(
        patch(&h, &token, &rs, json!({ "cimd_open": true }))
            .await
            .status(),
        StatusCode::OK
    );
    let id = format!("https://race.lifecycle.test/{}.json", h.suffix);
    let newcomer = format!("https://newcomer.lifecycle.test/{}.json", h.suffix);
    docs.publish_default(&id);
    docs.publish_default(&newcomer);
    let (_, refresh_token) = grant(&h, &id, &session, &rs, "mcp:read").await;
    let (code, pkce) = code_for(&h, &id, &session, &rs, "mcp:read").await;
    let uri = h.authorize_uri(&newcomer, &Pkce::generate(), Some(&rs), Some("mcp:read"));

    // Hold the policy lock and update without grant cleanup to exercise
    // the issuance recheck independently of the cleanup.
    let mut change = hold_policy_lock(reg).await;
    diesel::sql_query("UPDATE surge.oauth_resource SET cimd_open = FALSE WHERE id = $1")
        .bind::<diesel::sql_types::Uuid, _>(reg)
        .execute(&mut change)
        .await
        .unwrap();

    let h = std::sync::Arc::new(h);
    let authorizing = tokio::spawn({
        let h = h.clone();
        async move { h.get(&uri, Some(&session)).await }
    });
    let redeeming = tokio::spawn({
        let (h, id) = (h.clone(), id.clone());
        async move { redeem(&h, &id, &code, &pkce).await }
    });
    let rotating = tokio::spawn({
        let h = h.clone();
        async move { refresh(&h, &id, &refresh_token).await }
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while docs.fetches() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!authorizing.is_finished());
    assert!(!redeeming.is_finished());
    assert!(!rotating.is_finished());
    diesel::sql_query("COMMIT")
        .execute(&mut change)
        .await
        .unwrap();

    let response = authorizing.await.unwrap();
    assert_eq!(
        query_param(&location(&response), "error").as_deref(),
        Some("invalid_target")
    );
    assert!(h.engine.get_oauth_client(&newcomer).await.is_err());
    assert_eq!(redeeming.await.unwrap().0, StatusCode::BAD_REQUEST);
    assert_eq!(rotating.await.unwrap().0, StatusCode::BAD_REQUEST);
    assert_eq!(live_tokens(reg).await, 0);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_policy_change_waits_for_issuance_in_flight_and_then_ends_it() {
    let h = harness().await;
    let session = h.sign_in().await;
    let (_, token) = registrar(&h, "inflight").await;
    let rs = uri(&h, "inflight");
    let reg = register(&h, &token, &rs, &["mcp:read", "mcp:write"]).await;
    let c = client(&h, RegistrationSource::Admin, Some(vec![rs.clone()])).await;
    let (_, refresh_token) = grant(&h, &c, &session, &rs, "mcp:read mcp:write").await;

    // An issuance holds the registration's shared lock, as every
    // grant-creating write does, and has not committed yet.
    let mut issuing = db().await;
    diesel::sql_query("BEGIN").execute(&mut issuing).await.unwrap();
    diesel::sql_query("SELECT 1 FROM surge.oauth_resource WHERE id = $1 FOR SHARE")
        .bind::<diesel::sql_types::Uuid, _>(reg)
        .execute(&mut issuing)
        .await
        .unwrap();

    let h = std::sync::Arc::new(h);
    let patching = {
        let (h, token, rs) = (h.clone(), token.clone(), rs.clone());
        tokio::spawn(async move {
            patch(&h, &token, &rs, json!({ "scopes": ["mcp:read"] })).await.status()
        })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!patching.is_finished(), "a policy change ran through an issuance");
    // Shared locks do not block each other: issuance is not serialized
    // against itself.
    let (status, _) = refresh(&h, &c, &refresh_token).await;
    assert_eq!(status, StatusCode::OK);
    diesel::sql_query("COMMIT").execute(&mut issuing).await.unwrap();
    assert_eq!(patching.await.unwrap(), StatusCode::OK);

    // Everything issued before the change committed (the rotation's
    // successor included) was seen and ended by it.
    assert_eq!(live_tokens(reg).await, 0);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn racing_refreshes_against_policy_changes_never_leave_a_violating_grant() {
    let h = std::sync::Arc::new(harness().await);
    let session = h.sign_in().await;
    let (_, token) = registrar(&h, "race").await;

    for round in 0..8 {
        let rs = format!("https://race{round}.lifecycle.test/mcp-{}", h.suffix);
        let reg = register(&h, &token, &rs, &["mcp:read", "mcp:write"]).await;
        let bound = client(&h, RegistrationSource::Admin, Some(vec![rs.clone()])).await;
        // Each refresher rotates its own family: no replay detection, so
        // every rotation that wins the race writes a live successor that
        // only the locking keeps the patch from missing.
        let mut refreshers = Vec::new();
        for _ in 0..4 {
            let (_, first) = grant(&h, &bound, &session, &rs, "mcp:read mcp:write").await;
            let (h, bound) = (h.clone(), bound.clone());
            refreshers.push(tokio::spawn(async move {
                refresh(&h, &bound, &first).await.0
            }));
        }
        let patcher = {
            let (h, token, rs) = (h.clone(), token.clone(), rs.clone());
            tokio::spawn(async move {
                patch(&h, &token, &rs, json!({ "scopes": ["mcp:read"] })).await.status()
            })
        };
        assert_eq!(patcher.await.unwrap(), StatusCode::OK);
        for r in refreshers {
            let status = r.await.unwrap();
            assert!(status == StatusCode::OK || status == StatusCode::BAD_REQUEST);
        }

        // Whatever interleaving happened, no live token carries the scope.
        let violating: i64 = oauth_refresh_token::table
            .filter(oauth_refresh_token::registration_id.eq(reg))
            .filter(oauth_refresh_token::revoked_at.is_null())
            .filter(oauth_refresh_token::scopes.contains(vec!["mcp:write".to_string()]))
            .count()
            .get_result(&mut db().await)
            .await
            .unwrap();
        assert_eq!(violating, 0, "round {round}");
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn racing_deletion_against_refresh_leaves_no_live_grant() {
    // Deletion needs no extra locking against issuance to be safe: a refresh
    // token written for a registration that is being deleted is refused by
    // the composite foreign key, and the delete cascades whatever was
    // written before it. This test is a sanity check of that, not of the
    // lock; the lock's behaviour is covered by the lock-holding tests above.
    let h = std::sync::Arc::new(harness().await);
    let session = h.sign_in().await;
    let (_, token) = registrar(&h, "racedel").await;
    for round in 0..6 {
        let rs = format!("https://racedel{round}.lifecycle.test/mcp-{}", h.suffix);
        let reg = register(&h, &token, &rs, &["mcp:read"]).await;
        let c = client(&h, RegistrationSource::Admin, Some(vec![rs.clone()])).await;
        let (_, first) = grant(&h, &c, &session, &rs, "mcp:read").await;
        let refresher = {
            let (h, c, first) = (h.clone(), c.clone(), first.clone());
            tokio::spawn(async move { refresh(&h, &c, &first).await.1 })
        };
        let deleter = {
            let (h, token, rs) = (h.clone(), token.clone(), rs.clone());
            tokio::spawn(async move {
                call(&h, "DELETE", &format!("{}?registration_id={reg}", path(&rs)), &token, None)
                    .await
                    .status()
            })
        };
        assert_eq!(deleter.await.unwrap(), StatusCode::NO_CONTENT);
        refresher.await.unwrap();
        assert_eq!(live_tokens(reg).await, 0, "round {round}");
        assert!(h.engine.get_oauth_registration(reg).await.is_err());
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_saved_consent_removed_before_the_code_is_minted_is_not_relied_on() {
    let h = std::sync::Arc::new(harness().await);
    let session = h.sign_in().await;
    let (_, token) = registrar(&h, "consent").await;
    let rs = uri(&h, "consent");
    let reg = register(&h, &token, &rs, &["mcp:read"]).await;
    let c = client(&h, RegistrationSource::Admin, Some(vec![rs.clone()])).await;
    grant(&h, &c, &session, &rs, "mcp:read").await;
    assert!(consent_scopes(&h, &c, reg).await.is_some());

    // The authorize request reads the saved consent, then waits for the
    // registration lock a policy change holds...
    let mut change = hold_policy_lock(reg).await;
    let request = {
        let (h, c, rs, session) = (h.clone(), c.clone(), rs.clone(), session.clone());
        tokio::spawn(async move {
            let pkce = Pkce::generate();
            h.get(&h.authorize_uri(&c, &pkce, Some(&rs), Some("mcp:read")), Some(&session))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!request.is_finished());
    // ...during which the user withdraws the consent.
    h.engine.revoke_connection(h.identity_id().await, &c).await.unwrap();
    diesel::sql_query("COMMIT").execute(&mut change).await.unwrap();

    let resp = request.await.unwrap();
    let target = location(&resp);
    assert_eq!(
        query_param(&target, "error").as_deref(),
        Some("consent_required"),
        "{target}"
    );
    assert!(query_param(&target, "code").is_none());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn the_reservation_window_never_shrinks_below_the_recorded_lifetime() {
    let h = harness().await;
    let (_, token) = registrar(&h, "hw").await;
    // The server recorded its lifetime at startup.
    assert!(h.engine.access_ttl_high_water().await.unwrap().unwrap() >= Duration::from_secs(600));
    // A higher one is kept, a lower one is not.
    h.engine.raise_access_ttl_high_water(Duration::from_secs(3600)).await.unwrap();
    h.engine.raise_access_ttl_high_water(Duration::from_secs(60)).await.unwrap();
    let recorded = h.engine.access_ttl_high_water().await.unwrap().unwrap();
    assert!(recorded >= Duration::from_secs(3600));

    // A delete from a process that knows nothing of the configuration (the
    // CLI) reserves for the recorded lifetime, not a default.
    let rs = uri(&h, "hw");
    let id = register(&h, &token, &rs, &["mcp:read"]).await;
    h.engine
        .delete_oauth_resource(
            AuditActor::Operator { name: "t".into() },
            ResourceManager::Admin,
            &rs,
            Some(id),
            None,
        )
        .await
        .unwrap();
    let until: chrono::DateTime<chrono::Utc> = oauth_resource_reservation::table
        .find(&rs)
        .select(oauth_resource_reservation::reserved_until)
        .first(&mut db().await)
        .await
        .unwrap();
    assert!((until - chrono::Utc::now()).num_seconds() >= recorded.as_secs() as i64);
    let resp = call(
        &h,
        "POST",
        "/v1/oauth/resources",
        &token,
        Some(json!({ "resource_uri": rs, "scopes": ["mcp:read"] })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert!(body_json(resp).await["reserved_until"].is_string());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn description_keys_must_name_scopes_and_a_noop_dcr_flag_is_accepted() {
    let h = harness().await;
    let resp = patch(&h, &h.service_token, &h.resource_uri, json!({ "scope_descriptions": { "nope": "x" } })).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let resp = patch(&h, &h.service_token, &h.resource_uri, json!({ "dcr_enabled": false })).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn the_engine_refuses_a_delete_for_a_registrar_that_is_not_the_creator() {
    let h = harness().await;
    let (creator, token) = registrar(&h, "creator").await;
    let rs = uri(&h, "engine");
    let id = register(&h, &token, &rs, &["mcp:read"]).await;
    let outcome = h
        .engine
        .delete_oauth_resource(
            AuditActor::Operator { name: "t".into() },
            ResourceManager::Registrar(Uuid::now_v7()),
            &rs,
            Some(id),
            Some(Duration::ZERO),
        )
        .await;
    assert!(matches!(outcome, Err(surge_engine::AuthError::NotFound)));
    let outcome = h
        .engine
        .delete_oauth_resource(
            AuditActor::Operator { name: "t".into() },
            ResourceManager::Registrar(creator),
            &rs,
            Some(id),
            Some(Duration::ZERO),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, DeleteOutcome::Deleted(_)));
}
