//! The resource-server half, end to end (internal/oauth-as.md §6).
//!
//! Everything else in this suite drives the authorization server in-process
//! with `oneshot`. This one cannot: `surge::resource` discovers the JWKS URI
//! over HTTP from the AS metadata document, so the AS has to be listening on
//! a real socket. That discovery path — metadata, then JWKS, then offline
//! verification — is exactly what would break silently in production, so it
//! is worth the port.

mod oauth_support;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use oauth_support::*;
use secrecy::SecretString;
use serde_json::json;
use surge::resource::{AccessToken, ResourceServer, ResourceServerConfig, ScopeGuard};
use surge::{EmbeddedConfig, EmbeddedProvider};
use surge_server::config::{OauthAsSettings, ServerConfig};
use tower::ServiceExt;

/// Stands the AS up on a real loopback port and returns (issuer, app, engine,
/// resource_uri, suffix).
async fn listening_as() -> (String, Arc<surge_engine::Engine>, axum::Router, String, u32) {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run the OAuth authorization-server tests");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer = format!("http://{addr}");

    let embedded = Arc::new(
        EmbeddedProvider::new(EmbeddedConfig {
            database_url: SecretString::from(database_url),
            pepper: SecretString::from(TEST_PEPPER.to_string()),
            session_ttl: Duration::from_secs(3600),
        })
        .await
        .unwrap(),
    );
    let engine = embedded.engine();
    let suffix = rand_suffix();

    let token = surge_engine::types::ServiceToken::generate();
    engine
        .create_service(
            &format!("rs-svc-{suffix}"),
            token.hash(),
            vec!["introspect".to_string()],
            vec![issuer.clone()],
        )
        .await
        .unwrap();
    let service_id = engine
        .list_services()
        .await
        .unwrap()
        .into_iter()
        .find(|s| s.name == format!("rs-svc-{suffix}"))
        .unwrap()
        .id;

    let resource_uri = format!("https://rs.oauth.test/mcp-{suffix}");
    engine
        .create_oauth_resource(
            &resource_uri,
            service_id,
            vec!["mcp:read".to_string(), "mcp:write".to_string()],
            json!({}),
        )
        .await
        .unwrap();

    let config = Arc::new(ServerConfig {
        database_url: SecretString::from(String::new()),
        pepper: SecretString::from(String::new()),
        // Loopback, which is the one case where a plaintext issuer is
        // legitimate — nothing leaves the machine.
        bind_addr: "127.0.0.1:0".to_string(),
        cookie_domain: "oauth.test".to_string(),
        auth_ui_origin: AUTH_UI_ORIGIN.to_string(),
        session_ttl_hours: 1,
        registration: surge::router::RegistrationMode::Open,
        factor_policy: surge::router::FactorPolicy::None,
        session_cors_origins: vec![],
        allow_served_inline: true,
        hydra_bridge: None,
        oauth_as: Some(OauthAsSettings {
            issuer: issuer.clone(),
            access_ttl: Duration::from_secs(600),
            refresh_ttl: Duration::from_secs(30 * 86_400),
            key_rotation: Duration::from_secs(90 * 86_400),
            allow_dynamic_registration: false,
            require_resource: true,
            default_resource: None,
            dcr_ttl: Duration::from_secs(30 * 86_400),
            enable_oidc: true,
        }),
    });

    let app = surge_server::api::router(embedded, config).await.unwrap();

    let served = app.clone();
    tokio::spawn(async move {
        axum::serve(listener, served).await.unwrap();
    });

    (issuer, engine, app, resource_uri, suffix)
}

/// Mints an access token through the full authorize + token round trip.
async fn mint_access_token(
    app: &axum::Router,
    engine: &Arc<surge_engine::Engine>,
    resource_uri: &str,
    suffix: u32,
    scope: &str,
) -> String {
    let h = Harness {
        app: app.clone(),
        engine: Arc::clone(engine),
        service_token: String::new(),
        resource_uri: resource_uri.to_string(),
        suffix,
    };

    let username = format!("oauth-user-{suffix}");
    let password = "correct horse battery staple";
    let identity = engine
        .create_identity(
            &surge_engine::Username::new(&username).unwrap(),
            &username,
        )
        .await
        .unwrap();
    engine
        .set_password(
            identity.id,
            &surge_engine::Password::new(SecretString::from(password.to_string())).unwrap(),
        )
        .await
        .unwrap();
    let session = engine
        .mint_session(identity.id, surge_engine::AuthMethod::Password)
        .await
        .unwrap()
        .token
        .expose_secret()
        .to_string();

    let client_id = h.client(true).await;
    let pkce = Pkce::generate();
    let uri = h.authorize_uri(&client_id, &pkce, Some(resource_uri), Some(scope));
    let target = location(&h.get(&uri, Some(&session)).await);
    let code = query_param(&target, "code").expect("no code");

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

    tokens["access_token"]
        .as_str()
        .expect("no access token")
        .to_string()
}

fn resource_app(server: &Arc<ResourceServer>) -> Router {
    // The guard covers the protected route only. The metadata document is
    // fetched by a client that does not have a token yet — gating it would
    // make the resource undiscoverable.
    let protected = Router::new()
        .route(
            "/mcp",
            get(|AccessToken(claims): AccessToken| async move {
                axum::Json(json!({ "sub": claims.sub, "scope": claims.scope }))
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            ScopeGuard::new(server, ["mcp:read"]),
            surge::resource::require_scope,
        ));

    Router::new().merge(server.router()).merge(protected)
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_resource_server_verifies_a_real_token_offline() {
    let (issuer, engine, app, resource_uri, suffix) = listening_as().await;
    let access = mint_access_token(&app, &engine, &resource_uri, suffix, "mcp:read").await;

    let server = ResourceServer::new(ResourceServerConfig {
        issuer: issuer.clone(),
        resource_uri: resource_uri.clone(),
        required_scopes: vec![],
        jwks_cache_ttl: Duration::from_secs(60),
    })
    .unwrap();
    let rs = resource_app(&server);

    // The metadata document points an MCP client at the authorization server.
    let resp = rs
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri(server.metadata_path())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let metadata = body_json(resp).await;
    assert_eq!(metadata["resource"], resource_uri);
    assert_eq!(metadata["authorization_servers"][0], issuer);

    // An unauthenticated call is answered with the challenge that names that
    // document — the discovery mechanism, not merely an error.
    let resp = rs
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/mcp")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(challenge.contains(&format!("resource_metadata=\"{}\"", server.metadata_url())));

    // And a real token gets through, verified against JWKS the guard fetched
    // by way of the metadata document.
    let resp = rs
        .oneshot(
            axum::http::Request::builder()
                .uri("/mcp")
                .header("authorization", format!("Bearer {access}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["scope"], "mcp:read");
}

/// The property RFC 8707 exists for: a token minted for one audience must not
/// validate at another. Without this, every resource server that trusts this
/// issuer is a confused deputy for every other one.
#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_token_for_another_audience_does_not_validate_here() {
    let (issuer, engine, app, resource_uri, suffix) = listening_as().await;
    let access = mint_access_token(&app, &engine, &resource_uri, suffix, "mcp:read").await;

    let other = ResourceServer::new(ResourceServerConfig {
        issuer: issuer.clone(),
        resource_uri: format!("https://rs.oauth.test/other-{suffix}"),
        required_scopes: vec![],
        jwks_cache_ttl: Duration::from_secs(60),
    })
    .unwrap();

    let resp = resource_app(&other)
        .oneshot(
            axum::http::Request::builder()
                .uri("/mcp")
                .header("authorization", format!("Bearer {access}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("invalid_token"));
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_token_without_the_required_scope_is_forbidden_not_unauthorized() {
    let (issuer, engine, app, resource_uri, suffix) = listening_as().await;
    // Minted with mcp:read only; the guarded route below wants mcp:write.
    let access = mint_access_token(&app, &engine, &resource_uri, suffix, "mcp:read").await;

    let server = ResourceServer::new(ResourceServerConfig {
        issuer,
        resource_uri,
        required_scopes: vec!["mcp:write".to_string()],
        jwks_cache_ttl: Duration::from_secs(60),
    })
    .unwrap();

    let resp = resource_app(&server)
        .oneshot(
            axum::http::Request::builder()
                .uri("/mcp")
                .header("authorization", format!("Bearer {access}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // The token is valid; the grant is not sufficient. RFC 6750 distinguishes
    // these, and a client can act on the difference: re-authorize for a wider
    // scope rather than re-authenticate.
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(challenge.contains("insufficient_scope"));
}
