//! Per-resource DCR opt-in and scope ceilings.
//!
//! Anonymous registration may only see and use the scopes of service
//! resources and of delegated resources that opted in to DCR. The scope list
//! a client registers is a ceiling only if the registration asked for one;
//! either way what it may be granted is judged against the target's *current*
//! scopes, at authorization and at every refresh.

mod oauth_support;

use axum::http::StatusCode;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use oauth_support::*;
use serde_json::{Value, json};
use surge_engine::oauth::{NewOauthClient, RegistrationSource, ResourcePatch};
use surge_engine::schema::oauth_resource;

async fn dcr_harness() -> Harness {
    harness_with(|mut settings| {
        settings.allow_dynamic_registration = true;
        settings
    })
    .await
}

async fn delegated_resource(h: &Harness, name: &str, scopes: &[&str], dcr: bool) -> String {
    let uri = format!("https://{name}.oauth.test/mcp-{}", h.suffix);
    let registrar = h
        .engine
        .get_oauth_resource(&h.resource_uri)
        .await
        .unwrap()
        .service_id
        .unwrap();
    let mut conn = AsyncPgConnection::establish(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
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

async fn patch(h: &Harness, uri: &str, patch: ResourcePatch) {
    h.engine
        .update_oauth_resource(
            surge_engine::audit::AuditActor::Operator { name: "test".into() },
            surge_engine::oauth::ResourceManager::Admin,
            uri,
            None,
            patch,
        )
        .await
        .expect("update_oauth_resource");
}

async fn register(h: &Harness, body: Value) -> (StatusCode, Value) {
    let mut body = body;
    body["redirect_uris"] = json!([CLIENT_REDIRECT]);
    let resp = h.post_json("/oauth2/register", body, None).await;
    (resp.status(), body_json(resp).await)
}

async fn authorize(h: &Harness, client_id: &str, session: &str, resource: &str, scope: Option<&str>) -> String {
    let pkce = Pkce::generate();
    let resp = h
        .get(&h.authorize_uri(client_id, &pkce, Some(resource), scope), Some(session))
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    location(&resp)
}

/// Authorize -> consent -> code -> tokens. Returns the token response.
async fn full_grant(h: &Harness, client_id: &str, session: &str, resource: &str, scope: Option<&str>) -> Value {
    let pkce = Pkce::generate();
    let resp = h
        .get(&h.authorize_uri(client_id, &pkce, Some(resource), scope), Some(session))
        .await;
    let mut target = location(&resp);
    if let Some(flow) = query_param(&target, "consent_flow") {
        let csrf = body_json(h.get(&format!("/v1/oauth/consent/{flow}"), Some(session)).await).await
            ["csrf_token"]
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
        target = body_json(resp).await["redirect_to"].as_str().unwrap().to_string();
    }
    let code = query_param(&target, "code").unwrap_or_else(|| panic!("no code: {target}"));
    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", CLIENT_REDIRECT),
                ("client_id", client_id),
                ("code_verifier", &pkce.verifier),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await
}

async fn refresh(h: &Harness, client_id: &str, token: &str, scope: Option<&str>) -> (StatusCode, Value) {
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", token),
        ("client_id", client_id),
    ];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }
    let resp = h.post_form("/oauth2/token", &form).await;
    (resp.status(), body_json(resp).await)
}

fn scope_set(v: &Value) -> Vec<String> {
    let mut s: Vec<String> = v["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .map(String::from)
        .collect();
    s.sort();
    s
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn anonymous_registration_never_reveals_delegated_scopes_that_did_not_opt_in() {
    let h = dcr_harness().await;
    let hidden = format!("dlg:hidden-{}", h.suffix);
    let open = format!("dlg:open-{}", h.suffix);
    delegated_resource(&h, "closed", &[hidden.as_str()], false).await;
    delegated_resource(&h, "open", &[open.as_str()], true).await;

    // Defaults: service scopes plus opted-in delegated ones, nothing else.
    let (status, body) = register(&h, json!({})).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let scopes = scope_set(&body);
    assert!(scopes.contains(&"mcp:read".to_string()), "{scopes:?}");
    assert!(scopes.contains(&open), "{scopes:?}");
    assert!(!scopes.contains(&hidden), "{scopes:?}");

    // Asking for a hidden scope fails exactly like asking for an invented one.
    let (status_hidden, hidden_body) = register(&h, json!({ "scope": hidden })).await;
    let (status_nowhere, nowhere_body) =
        register(&h, json!({ "scope": "nowhere:nothing" })).await;
    assert_eq!(status_hidden, StatusCode::BAD_REQUEST);
    assert_eq!(status_hidden, status_nowhere);
    assert_eq!(hidden_body, nowhere_body);

    // Mixed: the hidden one is silently dropped, never echoed.
    let (status, body) = register(&h, json!({ "scope": format!("mcp:read {hidden}") })).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(scope_set(&body), vec!["mcp:read".to_string()]);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn registration_records_whether_a_scope_ceiling_was_requested() {
    let h = dcr_harness().await;

    let (_, omitted) = register(&h, json!({})).await;
    let stored = h
        .engine
        .get_oauth_client(omitted["client_id"].as_str().unwrap())
        .await
        .unwrap();
    assert!(!stored.scope_ceiling_explicit);

    let (_, asked) = register(&h, json!({ "scope": "mcp:read" })).await;
    let stored = h
        .engine
        .get_oauth_client(asked["client_id"].as_str().unwrap())
        .await
        .unwrap();
    assert!(stored.scope_ceiling_explicit);

    // Every other path, admin included, is an explicit ceiling.
    let admin = h.engine.get_oauth_client(&h.client(false).await).await.unwrap();
    assert!(admin.scope_ceiling_explicit);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn adding_write_never_widens_an_explicit_read_client_and_refresh_cannot_widen() {
    let h = dcr_harness().await;
    let session = h.sign_in().await;
    let rs = delegated_resource(&h, "grow", &["mcp:read"], true).await;

    let (_, explicit) = register(&h, json!({ "scope": "mcp:read", "resources": [rs] })).await;
    let (_, omitted) = register(&h, json!({ "resources": [rs] })).await;
    let explicit_id = explicit["client_id"].as_str().unwrap();
    let omitted_id = omitted["client_id"].as_str().unwrap();

    let e_tokens = full_grant(&h, explicit_id, &session, &rs, None).await;
    let o_tokens = full_grant(&h, omitted_id, &session, &rs, None).await;
    assert_eq!(scope_set(&e_tokens), vec!["mcp:read"]);
    assert_eq!(scope_set(&o_tokens), vec!["mcp:read"]);

    patch(
        &h,
        &rs,
        ResourcePatch {
            scopes: Some(vec!["mcp:read".into(), "mcp:write".into()]),
            ..Default::default()
        },
    )
    .await;

    // Authorization: write is refused for the explicit client...
    let target = authorize(&h, explicit_id, &session, &rs, Some("mcp:write")).await;
    assert_eq!(query_param(&target, "error").as_deref(), Some("invalid_scope"), "{target}");
    // ...and its default stays read.
    let tokens = full_grant(&h, explicit_id, &session, &rs, None).await;
    assert_eq!(scope_set(&tokens), vec!["mcp:read"]);

    // Refresh cannot widen past the grant, nor past the ceiling.
    let (status, body) =
        refresh(&h, explicit_id, e_tokens["refresh_token"].as_str().unwrap(), Some("mcp:read mcp:write")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_scope");
    let (status, body) =
        refresh(&h, omitted_id, o_tokens["refresh_token"].as_str().unwrap(), Some("mcp:write")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_scope");

    // The omitted-scope client may use the target's current scopes on a new
    // authorization.
    let tokens = full_grant(&h, omitted_id, &session, &rs, None).await;
    assert_eq!(scope_set(&tokens), vec!["mcp:read", "mcp:write"]);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn an_omitted_ceiling_client_gets_scopes_the_resource_gains_later() {
    let h = dcr_harness().await;
    let session = h.sign_in().await;
    let rs = delegated_resource(&h, "gain", &["dlg:a"], true).await;
    // Registered before `dlg:b` existed anywhere.
    let (_, reg) = register(&h, json!({ "resources": [rs] })).await;
    let id = reg["client_id"].as_str().unwrap();
    assert!(!scope_set(&reg).contains(&"dlg:b".to_string()));

    patch(
        &h,
        &rs,
        ResourcePatch {
            scopes: Some(vec!["dlg:a".into(), "dlg:b".into()]),
            ..Default::default()
        },
    )
    .await;
    let tokens = full_grant(&h, id, &session, &rs, Some("dlg:b")).await;
    assert_eq!(scope_set(&tokens), vec!["dlg:b"]);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_legacy_scope_list_is_an_explicit_ceiling() {
    // Clients created without stating provenance (every admin client, and
    // every row that predates the column) are explicit.
    let h = harness().await;
    let session = h.sign_in().await;
    let rs = delegated_resource(&h, "legacy", &["mcp:read"], false).await;
    let (client, _) = h
        .engine
        .create_oauth_client(NewOauthClient {
            client_name: "Legacy".into(),
            client_uri: None,
            logo_uri: None,
            redirect_uris: vec![CLIENT_REDIRECT.to_string()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            scopes: vec!["mcp:read".into()],
            confidential: false,
            first_party: false,
            registration_source: RegistrationSource::Admin,
            audiences: Some(vec![rs.clone()]),
        })
        .await
        .unwrap();
    assert!(client.scope_ceiling_explicit);
    patch(
        &h,
        &rs,
        ResourcePatch {
            scopes: Some(vec!["mcp:read".into(), "mcp:write".into()]),
            ..Default::default()
        },
    )
    .await;
    let target = authorize(&h, &client.client_id, &session, &rs, Some("mcp:write")).await;
    assert_eq!(query_param(&target, "error").as_deref(), Some("invalid_scope"), "{target}");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn disabling_opt_in_cuts_off_registered_dynamic_clients_end_to_end() {
    let h = dcr_harness().await;
    let session = h.sign_in().await;
    let rs = delegated_resource(&h, "cut", &["mcp:read"], true).await;

    // Unbound (defaults to opted-in resources via the no-list branch) and
    // explicitly bound clients, both through the real endpoint.
    let (_, bound) = register(&h, json!({ "scope": "mcp:read", "resources": [rs] })).await;
    let bound_id = bound["client_id"].as_str().unwrap();
    let tokens = full_grant(&h, bound_id, &session, &rs, None).await;
    let refresh_token = tokens["refresh_token"].as_str().unwrap().to_string();

    patch(&h, &rs, ResourcePatch { dcr_enabled: Some(false), ..Default::default() }).await;

    let (status, body) = refresh(&h, bound_id, &refresh_token, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let target = authorize(&h, bound_id, &session, &rs, None).await;
    assert_eq!(query_param(&target, "error").as_deref(), Some("invalid_target"), "{target}");

    // Registering against the closed resource is refused with the same
    // message as an unknown one.
    let (status, closed) = register(&h, json!({ "resources": [rs] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, unknown) = register(&h, json!({ "resources": ["https://nowhere.oauth.test/x"] })).await;
    assert_eq!(closed, unknown);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn the_global_switch_closes_registration_and_its_advertisement() {
    let h = harness().await;
    let delegated = delegated_resource(&h, "switch", &["mcp:read"], true).await;
    let (status, _) = register(&h, json!({ "resources": [delegated] })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let doc = body_json(h.get("/.well-known/oauth-authorization-server", None).await).await;
    assert!(doc["registration_endpoint"].is_null());
}
