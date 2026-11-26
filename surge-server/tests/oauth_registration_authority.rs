//! Who may register and see audiences: administrators, and Platform
//! registrars confined to the delegated resources they created.

mod oauth_support;

use axum::http::StatusCode;
use oauth_support::*;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn call(
    h: &Harness,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> axum::response::Response {
    let req = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            body.map(|b| b.to_string()).unwrap_or_default(),
        ))
        .unwrap();
    h.app.clone().oneshot(req).await.unwrap()
}

async fn status(
    h: &Harness,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> StatusCode {
    call(h, method, path, token, body).await.status()
}

async fn service(h: &Harness, label: &str, grants: &[&str]) -> (uuid::Uuid, String) {
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

async fn mint(h: &Harness, token: &str, body: Value) -> StatusCode {
    status(h, "POST", "/v1/oauth/clients", token, Some(body)).await
}

fn resource(uri: &str) -> Value {
    json!({ "resource_uri": uri, "scopes": ["mcp:read"] })
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn admin_post_defaults_to_a_service_registration() {
    let h = harness().await;
    let admin = h
        .engine
        .get_oauth_resource(&h.resource_uri)
        .await
        .unwrap()
        .service_id
        .unwrap();
    let uri = format!("{}-default", h.resource_uri);
    let resp = call(
        &h,
        "POST",
        "/v1/oauth/resources",
        &h.service_token,
        Some(resource(&uri)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(body["registration_source"], "service");
    assert_eq!(body["service_id"], json!(admin));
    assert_eq!(body["registrar_service_id"], json!(admin));

    // An administrator may also register a delegated resource, but it has no owner.
    let delegated = format!("{}-admin-delegated", h.resource_uri);
    let mut req = resource(&delegated);
    req["registration_source"] = json!("delegated");
    let resp = call(
        &h,
        "POST",
        "/v1/oauth/resources",
        &h.service_token,
        Some(req.clone()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(body["registration_source"], "delegated");
    assert!(body["service_id"].is_null());

    req["resource_uri"] = json!(format!("{delegated}-2"));
    req["owner_service_id"] = json!(admin);
    let resp = status(
        &h,
        "POST",
        "/v1/oauth/resources",
        &h.service_token,
        Some(req),
    )
    .await;
    assert_eq!(resp, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_platform_registrar_is_confined_to_its_own_delegated_resources() {
    let h = harness().await;
    let (platform_id, platform) = service(&h, "platform", &["oauth_resource_register"]).await;
    let (_, other_platform) = service(&h, "platform-b", &["oauth_resource_register"]).await;
    let (owner_id, _) = service(&h, "owner", &["introspect"]).await;
    let uri = format!("{}-dev", h.resource_uri);
    let post = "/v1/oauth/resources";

    // The registrar is the authenticated service and the resource is delegated.
    let resp = call(&h, "POST", post, &platform, Some(resource(&uri))).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let mine = body_json(resp).await;
    assert_eq!(mine["registration_source"], "delegated");
    assert_eq!(mine["registrar_service_id"], json!(platform_id));
    assert!(mine["service_id"].is_null());

    // No owner assignment, no service registration.
    let mut assigned = resource(&format!("{uri}-owned"));
    assigned["owner_service_id"] = json!(owner_id);
    assert_eq!(
        status(&h, "POST", post, &platform, Some(assigned.clone())).await,
        StatusCode::FORBIDDEN
    );
    assigned["registration_source"] = json!("delegated");
    assert_eq!(
        status(&h, "POST", post, &platform, Some(assigned)).await,
        StatusCode::FORBIDDEN
    );
    let mut service_reg = resource(&format!("{uri}-svc"));
    service_reg["registration_source"] = json!("service");
    assert_eq!(
        status(&h, "POST", post, &platform, Some(service_reg)).await,
        StatusCode::FORBIDDEN
    );
    // A registrar cannot claim to be someone else.
    let mut spoof = resource(&format!("{uri}-spoof"));
    spoof["registrar_service_id"] = json!(owner_id);
    assert_eq!(
        status(&h, "POST", post, &platform, Some(spoof)).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // Duplicates (including a trailing-slash alias) keep the original.
    let resp = status(
        &h,
        "POST",
        post,
        &other_platform,
        Some(resource(&format!("{uri}/"))),
    )
    .await;
    assert_eq!(resp, StatusCode::CONFLICT);
    let kept = h.engine.get_oauth_resource(&uri).await.unwrap();
    let id = mine["registration_id"].as_str().unwrap();
    assert_eq!(kept.registration_id.to_string(), id);
    assert_eq!(kept.registrar_service_id, Some(platform_id));

    // Listing and reading show only its own; another's is indistinguishable from missing.
    let listed = body_json(call(&h, "GET", post, &platform, None).await).await;
    let uris: Vec<_> = listed["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["resource_uri"].clone())
        .collect();
    assert_eq!(uris, vec![json!(uri)]);
    let one = format!("{post}/{id}");
    assert_eq!(
        status(&h, "GET", &one, &platform, None).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&h, "GET", &one, &other_platform, None).await,
        StatusCode::NOT_FOUND
    );
    let none = body_json(call(&h, "GET", post, &other_platform, None).await).await;
    assert!(none["resources"].as_array().unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn administrators_manage_legacy_registrations_and_others_need_a_grant() {
    let h = harness().await;
    let (_, platform) = service(&h, "platform", &["oauth_resource_register"]).await;
    let (_, nobody) = service(&h, "nobody", &["introspect"]).await;

    // The harness resource was created through the operator path: unknown registrar.
    let legacy = h.engine.get_oauth_resource(&h.resource_uri).await.unwrap();
    assert!(legacy.registrar_service_id.is_none());
    let path = format!("/v1/oauth/resources/{}", legacy.registration_id);
    assert_eq!(
        status(&h, "GET", &path, &h.service_token, None).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&h, "GET", &path, &platform, None).await,
        StatusCode::NOT_FOUND
    );
    let listed =
        body_json(call(&h, "GET", "/v1/oauth/resources", &h.service_token, None).await).await;
    assert!(
        listed["resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["registration_id"] == json!(legacy.registration_id))
    );

    assert_eq!(
        status(&h, "GET", "/v1/oauth/resources", &nobody, None).await,
        StatusCode::FORBIDDEN
    );
    let attempt = Some(resource("https://x.oauth.test/a"));
    assert_eq!(
        status(&h, "POST", "/v1/oauth/resources", &nobody, attempt).await,
        StatusCode::FORBIDDEN
    );
}

fn client_body(first_party: bool, resources: Value) -> Value {
    json!({
        "client_name": "dev app",
        "redirect_uris": [CLIENT_REDIRECT],
        "scopes": ["mcp:read"],
        "first_party": first_party,
        "resources": resources,
    })
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn platform_client_registration_is_bounded_to_its_own_resources() {
    let h = harness().await;
    let (platform_id, platform) = service(
        &h,
        "platform",
        &["oauth_resource_register", "oauth_client_register"],
    )
    .await;
    let (_, resource_only) = service(&h, "resources", &["oauth_resource_register"]).await;
    let (_, client_only) = service(&h, "clients", &["oauth_client_register"]).await;
    let uri = format!("{}-clients", h.resource_uri);
    let created = status(
        &h,
        "POST",
        "/v1/oauth/resources",
        &platform,
        Some(resource(&uri)),
    )
    .await;
    assert_eq!(created, StatusCode::CREATED);

    // A delegated registration an administrator made is not this registrar's.
    let admin_made = format!("{}-admin-made", h.resource_uri);
    let mut req = resource(&admin_made);
    req["registration_source"] = json!("delegated");
    let made = status(
        &h,
        "POST",
        "/v1/oauth/resources",
        &h.service_token,
        Some(req),
    )
    .await;
    assert_eq!(made, StatusCode::CREATED);

    let forbidden = StatusCode::FORBIDDEN;
    assert_eq!(
        mint(&h, &platform, client_body(true, json!([uri]))).await,
        forbidden
    );
    assert_eq!(
        mint(&h, &platform, client_body(false, json!([]))).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut absent = client_body(false, json!(null));
    absent.as_object_mut().unwrap().remove("resources");
    assert_eq!(
        mint(&h, &platform, absent).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // Operator-registered, administrator-made and unregistered resources are refused.
    for other in [&h.resource_uri, &admin_made, "https://nowhere.oauth.test/x"] {
        assert_eq!(
            mint(&h, &platform, client_body(false, json!([other]))).await,
            forbidden
        );
    }
    // One foreign resource among its own spoils the request.
    let mixed = json!([uri, h.resource_uri]);
    assert_eq!(
        mint(&h, &platform, client_body(false, mixed)).await,
        forbidden
    );
    // Each grant is needed on its own.
    assert_eq!(
        mint(&h, &resource_only, client_body(false, json!([uri]))).await,
        forbidden
    );
    assert_eq!(
        mint(&h, &client_only, client_body(false, json!([uri]))).await,
        forbidden
    );
    // The old field name is now rejected rather than ignored.
    let mut legacy = client_body(false, json!(null));
    legacy["audiences"] = json!([uri]);
    legacy.as_object_mut().unwrap().remove("resources");
    assert_eq!(
        mint(&h, &platform, legacy).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // Confidential clients are allowed and receive a secret once.
    let mut confidential = client_body(false, json!([format!("{uri}/")]));
    confidential["confidential"] = json!(true);
    let resp = call(
        &h,
        "POST",
        "/v1/oauth/clients",
        &platform,
        Some(confidential),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert!(body["client_secret"].is_string());
    assert_eq!(body["confidential"], true);
    assert_eq!(body["registration_source"], "platform");
    assert_eq!(body["registrar_service_id"], json!(platform_id));
    assert_eq!(body["first_party"], false);
    assert_eq!(body["trust_state"], "untrusted");
    assert_eq!(body["audiences"], json!([uri]));

    let resp = call(
        &h,
        "POST",
        "/v1/oauth/clients",
        &platform,
        Some(client_body(false, json!([uri]))),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert!(body["client_secret"].is_null());
    assert_eq!(body["audiences"], json!([uri]));
    let client_id = body["client_id"].as_str().unwrap().to_string();

    // The audit record names the registrar and the resources it was created for.
    {
        use diesel::prelude::*;
        use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
        use surge_engine::schema::audit_log;
        let mut conn = AsyncPgConnection::establish(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let (actor, subject) = audit_log::table
            .filter(audit_log::action.eq("create_oauth_client"))
            .filter(audit_log::subject.contains(json!({ "client_id": client_id })))
            .select((audit_log::actor, audit_log::subject))
            .first::<(Value, Value)>(&mut conn)
            .await
            .unwrap();
        assert_eq!(actor["id"], json!(platform_id));
        assert_eq!(subject["registrar_service_id"], json!(platform_id));
        assert_eq!(subject["resources"], json!([uri]));
        assert_eq!(subject["registration_source"], "platform");
    }

    // The grant gives no access to the registry's other client operations.
    assert_eq!(
        status(&h, "GET", "/v1/oauth/clients", &platform, None).await,
        forbidden
    );

    // Consent treats the client's self-declared name as untrusted.
    let session = h.sign_in().await;
    let pkce = Pkce::generate();
    let resp = h
        .get(
            &h.authorize_uri(&client_id, &pkce, Some(&uri), Some("mcp:read")),
            Some(&session),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let flow = query_param(&location(&resp), "consent_flow").expect("no consent flow");
    let flow = body_json(
        h.get(&format!("/v1/oauth/consent/{flow}"), Some(&session))
            .await,
    )
    .await;
    assert_eq!(flow["client"]["dynamically_registered"], true);
    assert_eq!(flow["client"]["first_party"], false);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn an_admin_may_name_resources_and_platform_clients_are_never_swept() {
    let h = harness().await;
    let body = client_body(false, json!([h.resource_uri]));
    let resp = call(
        &h,
        "POST",
        "/v1/oauth/clients",
        &h.service_token,
        Some(body),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(body["registration_source"], "admin");
    assert!(body["registrar_service_id"].is_null());
    assert_eq!(body["audiences"], json!([h.resource_uri]));

    // Platform clients are created unused and old enough to be swept if they
    // were dynamic; the sweep must leave them alone.
    let (_, platform) = service(
        &h,
        "platform",
        &["oauth_resource_register", "oauth_client_register"],
    )
    .await;
    let uri = format!("{}-sweep", h.resource_uri);
    let _ = status(
        &h,
        "POST",
        "/v1/oauth/resources",
        &platform,
        Some(resource(&uri)),
    )
    .await;
    let resp = call(
        &h,
        "POST",
        "/v1/oauth/clients",
        &platform,
        Some(client_body(false, json!([uri]))),
    )
    .await;
    let client_id = body_json(resp).await["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    h.engine
        .gc_unused_dynamic_clients(std::time::Duration::from_millis(1))
        .await
        .unwrap();
    assert!(h.engine.get_oauth_client(&client_id).await.is_ok());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_platform_client_cannot_bind_a_registration_it_no_longer_holds() {
    let h = harness().await;
    let (platform_id, _) = service(&h, "platform", &["oauth_client_register"]).await;
    let uri = format!("{}-race", h.resource_uri);
    let mine = h
        .engine
        .register_oauth_resource(
            surge_engine::audit::AuditActor::Operator {
                name: "test".into(),
            },
            platform_id,
            &uri,
            None,
            vec!["mcp:read".into()],
            json!({}),
        )
        .await
        .unwrap();
    h.engine
        .delete_oauth_resource(
            surge_engine::audit::AuditActor::Operator {
                name: "test".into(),
            },
            surge_engine::oauth::ResourceManager::Admin,
            &uri,
            None,
            Some(std::time::Duration::ZERO),
        )
        .await
        .unwrap();
    // The reservation is lapsed by hand: this test is about the race.
    {
        use diesel::prelude::*;
        use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
        let mut conn = AsyncPgConnection::establish(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        diesel::sql_query(
            "UPDATE surge.oauth_resource_reservation SET reserved_until = now() - interval '1 second'",
        )
        .execute(&mut conn)
        .await
        .unwrap();
    }
    // The URI is re-registered by an administrator after the check passed.
    h.engine
        .register_oauth_resource(
            surge_engine::audit::AuditActor::Operator {
                name: "test".into(),
            },
            uuid::Uuid::now_v7(),
            &uri,
            None,
            vec!["mcp:read".into()],
            json!({}),
        )
        .await
        .unwrap();
    let spec = || surge_engine::oauth::NewOauthClient {
        client_name: "dev app".into(),
        client_uri: None,
        logo_uri: None,
        redirect_uris: vec![CLIENT_REDIRECT.into()],
        grant_types: vec!["authorization_code".into()],
        scopes: vec!["mcp:read".into()],
        confidential: false,
        first_party: false,
        registration_source: surge_engine::oauth::RegistrationSource::Platform,
        audiences: None,
    };
    let err = h
        .engine
        .create_platform_oauth_client(platform_id, spec(), vec![mine.registration_id])
        .await;
    assert!(matches!(
        err,
        Err(surge_engine::types::AuthError::Forbidden)
    ));
    let clients = h.engine.list_oauth_clients().await.unwrap();
    assert!(
        clients
            .iter()
            .all(|c| c.registrar_service_id != Some(platform_id))
    );
}

/// The registrar's binding is not merely recorded: the shared eligibility
/// rule confines a Platform client to exactly the registrations it was bound
/// to, at authorization and at redemption.
#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_platform_client_is_issued_tokens_only_for_its_bound_resource() {
    let h = harness().await;
    let session = h.sign_in().await;
    let (_, platform) = service(
        &h,
        "platform",
        &["oauth_resource_register", "oauth_client_register"],
    )
    .await;
    let uri = format!("{}-delegated", h.resource_uri);
    let resp = call(
        &h,
        "POST",
        "/v1/oauth/resources",
        &platform,
        Some(resource(&uri)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = call(
        &h,
        "POST",
        "/v1/oauth/clients",
        &platform,
        Some(client_body(false, json!([uri]))),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    assert_eq!(created["audiences"], json!([uri]));
    let client_id = created["client_id"].as_str().unwrap().to_string();

    // The bound, delegated resource: authorize, consent, redeem.
    let pkce = Pkce::generate();
    let resp = h
        .get(
            &h.authorize_uri(&client_id, &pkce, Some(&uri), Some("mcp:read")),
            Some(&session),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let target = location(&resp);
    let flow = query_param(&target, "consent_flow")
        .unwrap_or_else(|| panic!("bound resource must reach consent: {target}"));
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
    let code = query_param(&redirect, "code").expect("code");
    let resp = h
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
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_json(resp).await["access_token"].is_string());

    // A first-party service resource the client was not bound to.
    let pkce = Pkce::generate();
    let resp = h
        .get(
            &h.authorize_uri(&client_id, &pkce, Some(&h.resource_uri), Some("mcp:read")),
            Some(&session),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let target = location(&resp);
    assert_eq!(
        query_param(&target, "error").as_deref(),
        Some("invalid_target"),
        "{target}"
    );
}
