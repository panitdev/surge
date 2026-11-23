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
    assert!(resp.is_client_error());
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
    assert!(
        status(&h, "POST", post, &platform, Some(spoof))
            .await
            .is_client_error()
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

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn platform_client_registration_is_bounded_to_its_own_resources() {
    let h = harness().await;
    let (_, platform) = service(
        &h,
        "platform",
        &["oauth_resource_register", "oauth_client_register"],
    )
    .await;
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

    let client = |first_party: bool, audiences: Value| {
        json!({
            "client_name": "dev app",
            "redirect_uris": ["https://client.oauth.test/cb"],
            "scopes": ["mcp:read"],
            "first_party": first_party,
            "audiences": audiences,
        })
    };

    assert_eq!(
        mint(&h, &platform, client(true, json!([uri]))).await,
        StatusCode::FORBIDDEN
    );
    // No audience, an operator-registered audience and another's are all refused.
    assert!(
        mint(&h, &platform, client(false, json!([])))
            .await
            .is_client_error()
    );
    assert_eq!(
        mint(&h, &platform, client(false, json!([h.resource_uri]))).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        mint(&h, &client_only, client(false, json!([uri]))).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        mint(&h, &platform, client(false, json!([uri]))).await,
        StatusCode::CREATED
    );

    // The grant gives no access to the registry's other client operations.
    assert_eq!(
        status(&h, "GET", "/v1/oauth/clients", &platform, None).await,
        StatusCode::FORBIDDEN
    );
}
