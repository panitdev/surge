//! Shared harness for the OAuth authorization-server tests.
//!
//! Like the rest of `surge-server/tests`, these run against a real Postgres
//! and are `#[ignore]`d by default:
//!
//! ```sh
//! DATABASE_URL=postgres://localhost/surge_oauth_test \
//!   cargo test -p surge-server --test oauth_token -- --ignored
//! ```
//!
//! Each run creates its own randomly-named service, identity, client and
//! resource, so runs do not collide; nothing here drops or truncates tables.
//!
//! **Pepper note.** OAuth signing keys are encrypted under the pepper and are
//! per-*deployment*, not per-test — so two test binaries sharing one
//! `DATABASE_URL` must also share a pepper, or the second one finds a key it
//! cannot decrypt. `cross_version_canary.rs` uses this same string for that
//! reason.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use secrecy::SecretString;
use serde_json::{json, Value};
use surge::{EmbeddedConfig, EmbeddedProvider};
use surge_engine::oauth::{NewOauthClient, RegistrationSource};
use surge_server::config::{OauthAsSettings, ServerConfig};
use tower::ServiceExt;

/// Shared with `cross_version_canary.rs` — see the pepper note above.
pub const TEST_PEPPER: &str = "surge-oauth-test-pepper";
pub const ISSUER: &str = "https://as.oauth.test";
pub const AUTH_UI_ORIGIN: &str = "https://auth.oauth.test";
pub const CLIENT_REDIRECT: &str = "https://client.oauth.test/callback";

pub struct Harness {
    pub app: axum::Router,
    pub engine: Arc<surge_engine::Engine>,
    pub service_token: String,
    pub resource_uri: String,
    pub suffix: u32,
}

pub async fn harness() -> Harness {
    harness_with(|settings| settings).await
}

/// The same harness with the AS settings adjusted — for the tests that are
/// specifically about a configuration knob (dynamic registration, say).
pub async fn harness_with(tune: impl FnOnce(OauthAsSettings) -> OauthAsSettings) -> Harness {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run the OAuth authorization-server tests");

    let embedded = Arc::new(
        EmbeddedProvider::new(EmbeddedConfig {
            database_url: SecretString::from(database_url),
            pepper: SecretString::from(TEST_PEPPER.to_string()),
            session_ttl: Duration::from_secs(3600),
        })
        .await
        .expect("failed to stand up EmbeddedProvider against DATABASE_URL"),
    );

    let engine = embedded.engine();
    let suffix = rand_suffix();

    let token = surge_engine::types::ServiceToken::generate();
    engine
        .create_service(
            &format!("oauth-svc-{suffix}"),
            token.hash(),
            vec![
                "direct_auth".to_string(),
                "introspect".to_string(),
                "revoke".to_string(),
                "oauth_admin".to_string(),
            ],
            // The issuer must be a registered return origin or the authorize
            // handler's bounce through GET /v1/login is rejected — the trap
            // `check_startup_coherence` guards.
            vec![ISSUER.to_string(), "https://client.oauth.test".to_string()],
        )
        .await
        .expect("create_service");

    let service_id = engine
        .list_services()
        .await
        .unwrap()
        .into_iter()
        .find(|s| s.name == format!("oauth-svc-{suffix}"))
        .unwrap()
        .id;

    let resource_uri = format!("https://rs.oauth.test/mcp-{suffix}");
    engine
        .create_oauth_resource(
            &resource_uri,
            service_id,
            vec!["mcp:read".to_string(), "mcp:write".to_string()],
            json!({
                "mcp:read": "Read your data",
                "mcp:write": "Change your data",
            }),
        )
        .await
        .expect("create_oauth_resource");

    let settings = tune(OauthAsSettings {
        issuer: ISSUER.to_string(),
        access_ttl: Duration::from_secs(600),
        refresh_ttl: Duration::from_secs(30 * 86_400),
        key_rotation: Duration::from_secs(90 * 86_400),
        allow_dynamic_registration: false,
        require_resource: true,
        default_resource: None,
        dcr_ttl: Duration::from_secs(30 * 86_400),
        enable_oidc: true,
    });

    let config = Arc::new(ServerConfig {
        database_url: SecretString::from(String::new()),
        pepper: SecretString::from(String::new()),
        bind_addr: String::new(),
        cookie_domain: "oauth.test".to_string(),
        auth_ui_origin: AUTH_UI_ORIGIN.to_string(),
        session_ttl_hours: 1,
        registration: surge::router::RegistrationMode::Open,
        factor_policy: surge::router::FactorPolicy::None,
        session_cors_origins: vec![],
        allow_served_inline: true,
        hydra_bridge: None,
        oauth_as: Some(settings),
    });

    let app = surge_server::api::router(embedded, config)
        .await
        .expect("router assembly");

    Harness {
        app,
        engine,
        service_token: token.expose_secret().to_string(),
        resource_uri,
        suffix,
    }
}

impl Harness {
    /// Registers an identity and logs it in, returning the raw
    /// `surge_session` cookie value.
    pub async fn sign_in(&self) -> String {
        let username = format!("oauth-user-{}", self.suffix);
        let password = "correct horse battery staple";

        let resp = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/register")
                    .header("authorization", format!("Bearer {}", self.service_token))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": username,
                            "password": password,
                            "display_name": username,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "register setup failed");

        let resp = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/login")
                    .header("accept", "application/json")
                    .header("origin", AUTH_UI_ORIGIN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_json(resp).await;
        let flow_id = body["flow_id"].as_str().unwrap().to_string();
        let csrf = body["csrf_token"].as_str().unwrap().to_string();

        let resp = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/flows/{flow_id}/password"))
                    .header("content-type", "application/json")
                    .header("origin", AUTH_UI_ORIGIN)
                    .body(Body::from(
                        json!({
                            "username": username,
                            "password": password,
                            "csrf_token": csrf,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "login failed");

        let set_cookie = resp
            .headers()
            .get("set-cookie")
            .expect("no session cookie")
            .to_str()
            .unwrap()
            .to_string();
        set_cookie
            .split(';')
            .next()
            .unwrap()
            .trim_start_matches("surge_session=")
            .to_string()
    }

    pub async fn identity_id(&self) -> surge_engine::IdentityId {
        let username =
            surge_engine::Username::new(&format!("oauth-user-{}", self.suffix)).unwrap();
        self.engine
            .get_identity_by_username(&username)
            .await
            .unwrap()
            .id
    }

    pub async fn client(&self, first_party: bool) -> String {
        self.client_with(first_party, vec![CLIENT_REDIRECT.to_string()], false)
            .await
            .0
    }

    pub async fn client_with(
        &self,
        first_party: bool,
        redirect_uris: Vec<String>,
        confidential: bool,
    ) -> (String, Option<String>) {
        let (client, secret) = self
            .engine
            .create_oauth_client(NewOauthClient {
                client_name: format!("Test client {}", self.suffix),
                client_uri: None,
                logo_uri: None,
                redirect_uris,
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ],
                scopes: vec!["mcp:read".to_string(), "mcp:write".to_string()],
                confidential,
                first_party,
                registration_source: RegistrationSource::Admin,
            })
            .await
            .expect("create_oauth_client");

        (
            client.client_id,
            secret.map(|s| s.expose_secret().to_string()),
        )
    }

    pub async fn get(&self, uri: &str, session: Option<&str>) -> axum::response::Response {
        let mut builder = Request::builder().method("GET").uri(uri);
        if let Some(session) = session {
            builder = builder.header("cookie", format!("surge_session={session}"));
        }
        self.app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    pub async fn post_form(&self, uri: &str, form: &[(&str, &str)]) -> axum::response::Response {
        let body = form
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// A session-authenticated DELETE, carrying the header-CSRF the
    /// session-management zone requires.
    pub async fn delete(&self, uri: &str, session: &str) -> axum::response::Response {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(uri)
                    .header("cookie", format!("surge_session={session}"))
                    .header("x-surge-csrf", "1")
                    .header("origin", AUTH_UI_ORIGIN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    pub async fn introspect(&self, token: &str, service_token: &str) -> axum::response::Response {
        let body = format!("token={}", percent_encode(token));
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/introspect")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("authorization", format!("Bearer {service_token}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    pub async fn bearer_get(&self, uri: &str, token: &str) -> axum::response::Response {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    pub async fn post_json(
        &self,
        uri: &str,
        body: Value,
        session: Option<&str>,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("origin", AUTH_UI_ORIGIN);
        if let Some(session) = session {
            builder = builder.header("cookie", format!("surge_session={session}"));
        }
        self.app
            .clone()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    /// Drives a full authorization for a first-party client and returns the
    /// code from the redirect.
    pub async fn authorize_code(
        &self,
        client_id: &str,
        session: &str,
        pkce: &Pkce,
    ) -> String {
        let uri = self.authorize_uri(client_id, pkce, Some(&self.resource_uri), Some("mcp:read"));
        let resp = self.get(&uri, Some(session)).await;
        assert_eq!(
            resp.status(),
            StatusCode::SEE_OTHER,
            "authorize did not redirect to the client"
        );
        let target = location(&resp);
        query_param(&target, "code").unwrap_or_else(|| panic!("no code in redirect: {target}"))
    }

    pub fn authorize_uri(
        &self,
        client_id: &str,
        pkce: &Pkce,
        resource: Option<&str>,
        scope: Option<&str>,
    ) -> String {
        let mut uri = format!(
            "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=xyz",
            percent_encode(client_id),
            percent_encode(CLIENT_REDIRECT),
            percent_encode(&pkce.challenge),
        );
        if let Some(resource) = resource {
            uri.push_str(&format!("&resource={}", percent_encode(resource)));
        }
        if let Some(scope) = scope {
            uri.push_str(&format!("&scope={}", percent_encode(scope)));
        }
        uri
    }
}

/// An RFC 7636 verifier/challenge pair.
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn generate() -> Self {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};

        let verifier: String = format!("{:0>43}", rand_suffix());
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        Self {
            verifier,
            challenge,
        }
    }
}

pub fn location(resp: &axum::response::Response) -> String {
    resp.headers()
        .get(axum::http::header::LOCATION)
        .expect("no Location header")
        .to_str()
        .unwrap()
        .to_string()
}

/// Pulls one query parameter out of a redirect target.
pub fn query_param(url: &str, key: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    parsed
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

pub async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

pub async fn body_text(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn rand_suffix() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
        ^ std::process::id()
}

pub fn percent_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
