//! Audience and scope policy throughout issuance.
//!
//! One eligibility rule (`surge_engine::oauth::client_may_use_resource`) is
//! applied at authorization, consent completion, code redemption and refresh.
//! These tests drive each of those through HTTP, and change the policy
//! *between* stages to show that no stage trusts the one before it.

mod oauth_support;

use axum::http::StatusCode;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use oauth_support::*;
use serde_json::{Value, json};
use surge_engine::oauth::{NewOauthClient, RegistrationSource};
use surge_engine::schema::{oauth_client_audience, oauth_resource};

async fn db() -> AsyncPgConnection {
    AsyncPgConnection::establish(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap()
}

/// A second service resource that shares `mcp:read` with the harness's own.
async fn second_service_resource(h: &Harness) -> String {
    let uri = format!("https://rs2.oauth.test/mcp-{}", h.suffix);
    let owner = h
        .engine
        .get_oauth_resource(&h.resource_uri)
        .await
        .unwrap()
        .service_id
        .unwrap();
    h.engine
        .create_oauth_resource(
            &uri,
            owner,
            vec!["mcp:read".to_string()],
            json!({ "mcp:read": "Read the other thing" }),
        )
        .await
        .unwrap();
    uri
}

/// A delegated registration, inserted directly: the registration API that
/// creates them belongs to a different change.
async fn delegated_resource(h: &Harness, name: &str, scopes: &[&str], dcr: bool) -> String {
    let uri = format!("https://{name}.oauth.test/mcp-{}", h.suffix);
    let registrar = h
        .engine
        .get_oauth_resource(&h.resource_uri)
        .await
        .unwrap()
        .service_id
        .unwrap();
    let mut conn = db().await;
    diesel::insert_into(oauth_resource::table)
        .values((
            oauth_resource::id.eq(uuid::Uuid::now_v7()),
            oauth_resource::resource_uri.eq(&uri),
            oauth_resource::registration_source.eq("delegated"),
            oauth_resource::registrar_service_id.eq(Some(registrar)),
            oauth_resource::scopes.eq(scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            oauth_resource::scope_descriptions.eq(json!({})),
            oauth_resource::dcr_enabled.eq(dcr),
        ))
        .execute(&mut conn)
        .await
        .unwrap();
    uri
}

async fn client(
    h: &Harness,
    first_party: bool,
    source: RegistrationSource,
    audiences: Option<Vec<String>>,
) -> String {
    h.engine
        .create_oauth_client(NewOauthClient {
            client_name: format!("Policy client {}", h.suffix),
            client_uri: None,
            logo_uri: None,
            redirect_uris: vec![CLIENT_REDIRECT.to_string()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            scopes: vec!["mcp:read".into(), "mcp:write".into()],
            confidential: false,
            first_party,
            registration_source: source,
            audiences,
        })
        .await
        .expect("create_oauth_client")
        .0
        .client_id
}

/// Authorizes and returns the redirect target.
async fn authorize(h: &Harness, client_id: &str, session: &str, resource: &str) -> (Pkce, String) {
    let pkce = Pkce::generate();
    let resp = h
        .get(
            &h.authorize_uri(client_id, &pkce, Some(resource), Some("mcp:read")),
            Some(session),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let target = location(&resp);
    (pkce, target)
}

fn assert_invalid_target(target: &str) {
    assert_eq!(
        query_param(target, "error").as_deref(),
        Some("invalid_target"),
        "{target}"
    );
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

async fn drop_approvals(client_id: &str) {
    let mut conn = db().await;
    diesel::delete(
        oauth_client_audience::table.filter(oauth_client_audience::client_id.eq(client_id)),
    )
    .execute(&mut conn)
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn an_empty_audience_list_grants_no_access() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = client(&h, true, RegistrationSource::Admin, Some(vec![])).await;

    let (_, target) = authorize(&h, &client_id, &session, &h.resource_uri).await;
    assert_invalid_target(&target);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_client_without_a_list_keeps_its_access_to_service_resources() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = client(&h, true, RegistrationSource::Admin, None).await;

    let (_, target) = authorize(&h, &client_id, &session, &h.resource_uri).await;
    assert!(query_param(&target, "code").is_some(), "{target}");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn two_resources_sharing_a_scope_stay_isolated() {
    let h = harness().await;
    let session = h.sign_in().await;
    let other = second_service_resource(&h).await;
    let client_id = client(
        &h,
        false,
        RegistrationSource::Admin,
        Some(vec![h.resource_uri.clone()]),
    )
    .await;

    // The list restricts service resources too, even though both define
    // `mcp:read` and the client is allowed that scope.
    let (_, target) = authorize(&h, &client_id, &session, &other).await;
    assert_invalid_target(&target);

    // Consent for the listed one is its own: it covers nothing at the other,
    // for a client that is bound to both.
    let both = client(
        &h,
        false,
        RegistrationSource::Admin,
        Some(vec![h.resource_uri.clone(), other.clone()]),
    )
    .await;
    let (pkce, target) = authorize(&h, &both, &session, &h.resource_uri).await;
    let flow = query_param(&target, "consent_flow").expect("consent for the first resource");
    let csrf = body_json(
        h.get(&format!("/v1/oauth/consent/{flow}"), Some(&session))
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
            Some(&session),
        )
        .await;
    let redirect = body_json(resp).await["redirect_to"]
        .as_str()
        .unwrap()
        .to_string();
    let code = query_param(&redirect, "code").unwrap();
    let (status, tokens) = redeem(&h, &both, &code, &pkce).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");

    let (_, target) = authorize(&h, &both, &session, &other).await;
    assert!(
        query_param(&target, "consent_flow").is_some(),
        "consent at one resource must not carry to another, got {target}"
    );
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_code_is_not_redeemable_once_its_client_loses_the_audience() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = client(
        &h,
        true,
        RegistrationSource::Admin,
        Some(vec![h.resource_uri.clone()]),
    )
    .await;
    let (pkce, target) = authorize(&h, &client_id, &session, &h.resource_uri).await;
    let code = query_param(&target, "code").expect("authorized while approved");

    drop_approvals(&client_id).await;

    let (status, body) = redeem(&h, &client_id, &code, &pkce).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_target");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_refresh_is_refused_once_its_client_loses_the_audience() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = client(
        &h,
        true,
        RegistrationSource::Admin,
        Some(vec![h.resource_uri.clone()]),
    )
    .await;
    let (pkce, target) = authorize(&h, &client_id, &session, &h.resource_uri).await;
    let code = query_param(&target, "code").unwrap();
    let (status, tokens) = redeem(&h, &client_id, &code, &pkce).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let refresh = tokens["refresh_token"].as_str().unwrap();

    drop_approvals(&client_id).await;

    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_target");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn consent_cannot_be_completed_once_the_client_loses_the_audience() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = client(
        &h,
        false,
        RegistrationSource::Admin,
        Some(vec![h.resource_uri.clone()]),
    )
    .await;
    let (_, target) = authorize(&h, &client_id, &session, &h.resource_uri).await;
    let flow = query_param(&target, "consent_flow").unwrap();
    let csrf = body_json(
        h.get(&format!("/v1/oauth/consent/{flow}"), Some(&session))
            .await,
    )
    .await["csrf_token"]
        .as_str()
        .unwrap()
        .to_string();

    drop_approvals(&client_id).await;

    let resp = h
        .post_json(
            &format!("/v1/oauth/consent/{flow}"),
            json!({ "approve": true, "csrf_token": csrf }),
            Some(&session),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let redirect = body_json(resp).await["redirect_to"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(redirect.starts_with(CLIENT_REDIRECT));
    assert_invalid_target(&redirect);
    assert!(query_param(&redirect, "code").is_none());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn delegated_resources_need_a_binding_a_cimd_entry_or_a_dcr_opt_in() {
    let h = harness().await;
    let session = h.sign_in().await;
    let closed = delegated_resource(&h, "closed", &["mcp:read"], false).await;
    let open = delegated_resource(&h, "open", &["mcp:read"], true).await;

    // No list: service access only. An admin client gets nothing delegated,
    // not even from a DCR opt-in, which is for dynamic clients.
    let legacy = client(&h, true, RegistrationSource::Admin, None).await;
    for uri in [&closed, &open] {
        let (_, target) = authorize(&h, &legacy, &session, uri).await;
        assert_invalid_target(&target);
    }

    // An explicit binding is enough for an admin client.
    let bound = client(
        &h,
        true,
        RegistrationSource::Admin,
        Some(vec![closed.clone()]),
    )
    .await;
    let (_, target) = authorize(&h, &bound, &session, &closed).await;
    assert!(query_param(&target, "code").is_some(), "{target}");

    // A dynamic client reaches only resources that opted in.
    let dynamic = client(&h, false, RegistrationSource::Dynamic, None).await;
    let (_, target) = authorize(&h, &dynamic, &session, &closed).await;
    assert_invalid_target(&target);
    let (_, target) = authorize(&h, &dynamic, &session, &open).await;
    assert!(query_param(&target, "consent_flow").is_some(), "{target}");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_dynamic_client_cannot_bind_itself_to_a_resource_that_has_not_opted_in() {
    let h = harness_with(|mut settings| {
        settings.allow_dynamic_registration = true;
        settings
    })
    .await;
    let closed = delegated_resource(&h, "closed", &["mcp:read"], false).await;
    let open = delegated_resource(&h, "open", &["mcp:read"], true).await;

    let register = |resources: Value| {
        h.post_json(
            "/oauth2/register",
            json!({
                "redirect_uris": [CLIENT_REDIRECT],
                "scope": "mcp:read",
                "resources": resources,
            }),
            None,
        )
    };

    let resp = register(json!([closed])).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let closed_body = body_json(resp).await;
    assert_eq!(closed_body["error"], "invalid_client_metadata");

    let resp = register(json!(["https://nowhere.oauth.test/mcp"])).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let unknown_body = body_json(resp).await;
    assert_eq!(unknown_body["error"], "invalid_client_metadata");
    // Unauthenticated callers cannot tell "unknown" from "not opted in".
    assert_eq!(closed_body, unknown_body);

    let resp = register(json!([open])).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let registered = body_json(resp).await;
    assert_eq!(registered["resources"], json!([open]));
    let client_id = registered["client_id"].as_str().unwrap().to_string();
    let stored = h.engine.get_oauth_client(&client_id).await.unwrap();
    assert_eq!(stored.audiences, Some(vec![open.clone()]));

    // Service resources can be listed, which restricts the client to them.
    let resp = register(json!([h.resource_uri])).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn issuer_discovery_omits_scopes_only_delegated_resources_define() {
    let h = harness().await;
    let only = format!("dlg:only-{}", h.suffix);
    delegated_resource(&h, "closed", &[only.as_str()], false).await;
    let only_dcr = format!("dlg:dcr-{}", h.suffix);
    delegated_resource(&h, "open", &[only_dcr.as_str()], true).await;

    let doc = body_json(h.get("/.well-known/oauth-authorization-server", None).await).await;
    let scopes: Vec<&str> = doc["scopes_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert!(
        scopes.contains(&"mcp:read"),
        "service scopes stay: {scopes:?}"
    );
    assert!(!scopes.contains(&only.as_str()), "{scopes:?}");
    assert!(!scopes.contains(&only_dcr.as_str()), "{scopes:?}");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn introspection_never_answers_for_a_delegated_registration() {
    let h = harness().await;
    let session = h.sign_in().await;
    let delegated = delegated_resource(&h, "closed", &["mcp:read"], false).await;
    let client_id = client(
        &h,
        true,
        RegistrationSource::Admin,
        Some(vec![delegated.clone()]),
    )
    .await;

    let (pkce, target) = authorize(&h, &client_id, &session, &delegated).await;
    let code = query_param(&target, "code").unwrap();
    let (status, tokens) = redeem(&h, &client_id, &code, &pkce).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let access = tokens["access_token"].as_str().unwrap();

    // The harness service holds `introspect` and is the registrar, which is
    // not ownership: delegated registrations are owned by no service.
    let body = body_json(h.introspect(access, &h.service_token).await).await;
    assert_eq!(body["active"], false);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn an_ineligible_refresh_ends_the_grant() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = client(
        &h,
        true,
        RegistrationSource::Admin,
        Some(vec![h.resource_uri.clone()]),
    )
    .await;
    let (pkce, target) = authorize(&h, &client_id, &session, &h.resource_uri).await;
    let code = query_param(&target, "code").unwrap();
    let (_, tokens) = redeem(&h, &client_id, &code, &pkce).await;
    let access = tokens["access_token"].as_str().unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let live = body_json(h.introspect(access, &h.service_token).await).await;
    assert_eq!(live["active"], true);

    drop_approvals(&client_id).await;

    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(body_json(resp).await["error"], "invalid_target");

    // No live successor is left behind: the grant is not live, so the access
    // token already issued stops introspecting as active.
    let after = body_json(h.introspect(access, &h.service_token).await).await;
    assert_eq!(after["active"], false);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn an_unknown_resource_looks_like_an_ineligible_one() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = client(&h, true, RegistrationSource::Admin, Some(vec![])).await;
    let pkce = Pkce::generate();

    let unknown = location(
        &h.get(
            &h.authorize_uri(&client_id, &pkce, Some("https://nope.oauth.test/mcp"), None),
            Some(&session),
        )
        .await,
    );
    let (_, ineligible) = authorize(&h, &client_id, &session, &h.resource_uri).await;
    assert_invalid_target(&unknown);
    assert_eq!(
        query_param(&unknown, "error_description"),
        query_param(&ineligible, "error_description")
    );
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn tokens_without_the_access_token_type_or_from_the_future_are_refused() {
    let h = harness().await;
    let session = h.sign_in().await;
    let sub = h.identity_id().await.to_string();
    // A real, live grant, so introspection would say `active` if only the
    // header or `iat` were wrong.
    let client_id = client(&h, true, RegistrationSource::Admin, None).await;
    let (pkce, target) = authorize(&h, &client_id, &session, &h.resource_uri).await;
    let code = query_param(&target, "code").unwrap();
    let (status, _) = redeem(&h, &client_id, &code, &pkce).await;
    assert_eq!(status, StatusCode::OK);
    let claims = |iat| {
        let mut c = access_claims(ISSUER, &sub, &h.resource_uri, "openid mcp:read", iat);
        c["client_id"] = json!(client_id);
        c
    };

    let good = forge_jwt(&h.engine, Some("at+jwt"), claims(0)).await;
    assert_eq!(
        h.bearer_get("/oauth2/userinfo", &good).await.status(),
        StatusCode::OK
    );
    let body = body_json(h.introspect(&good, &h.service_token).await).await;
    assert_eq!(body["active"], true);

    let mut refused = vec![
        forge_jwt(&h.engine, None, claims(0)).await,
        forge_jwt(&h.engine, Some("JWT"), claims(0)).await,
        forge_jwt(&h.engine, Some("at+jwt"), claims(3600)).await,
    ];
    // An ID token as the AS signs it: no typ, audience is the client.
    let mut id_token = claims(0);
    id_token["aud"] = json!("aeg_cid_someclient");
    refused.push(forge_jwt(&h.engine, None, id_token).await);

    for token in refused {
        let resp = h.bearer_get("/oauth2/userinfo", &token).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(h.introspect(&token, &h.service_token).await).await;
        assert_eq!(body["active"], false);
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn the_service_api_binds_a_new_client_to_resources() {
    use tower::ServiceExt;
    let h = harness().await;
    let create = |resources: Value| {
        h.app.clone().oneshot(
            axum::http::Request::post("/v1/oauth/clients")
                .header("authorization", format!("Bearer {}", h.service_token))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    json!({
                        "client_name": "Bound",
                        "redirect_uris": [CLIENT_REDIRECT],
                        "scopes": ["mcp:read"],
                        "resources": resources,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
    };

    let resp = create(json!([h.resource_uri])).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let client_id = body_json(resp).await["client_id"].as_str().unwrap().to_string();
    let stored = h.engine.get_oauth_client(&client_id).await.unwrap();
    assert_eq!(stored.audiences, Some(vec![h.resource_uri.clone()]));

    let resp = create(json!(["https://nowhere.oauth.test/mcp"])).await.unwrap();
    assert!(resp.status().is_client_error(), "{}", resp.status());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn an_ineligible_refresh_ends_every_family_at_that_registration() {
    let h = harness().await;
    let session = h.sign_in().await;
    let client_id = client(
        &h,
        true,
        RegistrationSource::Admin,
        Some(vec![h.resource_uri.clone()]),
    )
    .await;

    let mut grants = vec![];
    for _ in 0..2 {
        let (pkce, target) = authorize(&h, &client_id, &session, &h.resource_uri).await;
        let code = query_param(&target, "code").unwrap();
        let (status, tokens) = redeem(&h, &client_id, &code, &pkce).await;
        assert_eq!(status, StatusCode::OK, "{tokens}");
        grants.push(tokens);
    }
    for tokens in &grants {
        let access = tokens["access_token"].as_str().unwrap();
        let body = body_json(h.introspect(access, &h.service_token).await).await;
        assert_eq!(body["active"], true);
    }

    drop_approvals(&client_id).await;

    // Only the first family refreshes; the second must die with it.
    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", grants[0]["refresh_token"].as_str().unwrap()),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(body_json(resp).await["error"], "invalid_target");

    for tokens in &grants {
        let access = tokens["access_token"].as_str().unwrap();
        let body = body_json(h.introspect(access, &h.service_token).await).await;
        assert_eq!(body["active"], false);
    }
}
