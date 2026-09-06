//! The resource-server half: what a service exposing an MCP endpoint (or any
//! other audience) needs in order to *accept* tokens this authorization
//! server issues.
//!
//! Three things are the same code in every service, so `surge` ships them
//! rather than having each one reimplement them:
//!
//! 1. publish RFC 9728 protected-resource metadata,
//! 2. answer an unauthenticated call with a `WWW-Authenticate` challenge that
//!    points at that metadata — this is how an MCP client discovers where to
//!    authorize,
//! 3. validate bearer tokens offline against cached JWKS.
//!
//! This mirrors what `AuthProvider` does for sessions: the service holds a
//! config object and never learns the protocol.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use std::time::Duration;
//! # async fn example() -> anyhow::Result<()> {
//! use surge::resource::{ResourceServer, ResourceServerConfig, ScopeGuard};
//!
//! let server = ResourceServer::new(ResourceServerConfig {
//!     issuer: "https://auth.panit.dev".into(),
//!     resource_uri: "https://dispatch.panit.dev/mcp".into(),
//!     required_scopes: vec!["mcp:read".into()],
//!     jwks_cache_ttl: Duration::from_secs(300),
//! })?;
//!
// The guard goes on the protected routes only. Layering it over the
//! // metadata document would make this resource undiscoverable: a client
//! // fetches that unauthenticated, precisely because it does not yet have
//! // a token.
//! let protected = axum::Router::new()
//!     .route("/mcp", axum::routing::post(|| async { "ok" }))
//!     .layer(axum::middleware::from_fn_with_state(
//!         ScopeGuard::new(&server, ["mcp:read"]),
//!         surge::resource::require_scope,
//!     ));
//!
//! let app = axum::Router::new()
//!     .merge(server.router())
//!     .merge(protected);
//! # let _ = app;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// What a resource server needs to know. Everything else — where the keys
/// are, how often to refetch them — is discovered or defaulted.
#[derive(Clone, Debug)]
pub struct ResourceServerConfig {
    /// The authorization server's issuer. Tokens whose `iss` is anything else
    /// are rejected, which is also what makes a two-issuer cutover explicit
    /// rather than accidental (internal/oauth-as.md §9).
    pub issuer: String,
    /// This resource's canonical audience URI. A token minted for another
    /// resource must not validate here, and this is the check that ensures it.
    pub resource_uri: String,
    /// Scopes every request to the guarded routes must carry.
    pub required_scopes: Vec<String>,
    pub jwks_cache_ttl: Duration,
}

/// The claims a verified access token carries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceClaims {
    pub iss: String,
    /// The Surge identity UUID.
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub scope: String,
    pub sid: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
}

impl ResourceClaims {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.split_whitespace().any(|s| s == scope)
    }

    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.scope.split_whitespace()
    }
}

pub struct ResourceServer {
    config: ResourceServerConfig,
    client: reqwest::Client,
    /// One entry, keyed by unit: the JWKS document. Cached because a key
    /// fetch per request would make offline verification pointless.
    jwks: Cache<(), Arc<Vec<serde_json::Value>>>,
}

impl ResourceServer {
    pub fn new(config: ResourceServerConfig) -> Result<Arc<Self>, anyhow::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        let jwks = Cache::builder()
            .max_capacity(1)
            .time_to_live(config.jwks_cache_ttl)
            .build();

        Ok(Arc::new(Self {
            config,
            client,
            jwks,
        }))
    }

    pub fn config(&self) -> &ResourceServerConfig {
        &self.config
    }

    /// Mounts the RFC 9728 metadata document. The path is fixed by the RFC
    /// at the origin root — it cannot be nested under a version prefix — so
    /// this router is merged, not nested.
    ///
    /// A resource URI with a path gets the path *appended to the well-known
    /// prefix* (RFC 9728 §3): `https://rs.example/mcp` is described at
    /// `https://rs.example/.well-known/oauth-protected-resource/mcp`, not at
    /// `…/mcp/.well-known/…`. Getting this backwards is the most common way
    /// a resource server ends up undiscoverable.
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route(&self.metadata_path(), get(protected_resource_metadata))
            .with_state(Arc::clone(self))
    }

    /// The path this server's metadata is served at, per RFC 9728 §3.
    pub fn metadata_path(&self) -> String {
        let path = url::Url::parse(&self.config.resource_uri)
            .ok()
            .map(|u| u.path().trim_end_matches('/').to_string())
            .unwrap_or_default();
        format!("/.well-known/oauth-protected-resource{path}")
    }

    /// The absolute URL of that document — what the `WWW-Authenticate`
    /// challenge points at.
    pub fn metadata_url(&self) -> String {
        match url::Url::parse(&self.config.resource_uri) {
            Ok(url) => {
                let origin = format!(
                    "{}://{}{}",
                    url.scheme(),
                    url.host_str().unwrap_or_default(),
                    url.port().map(|p| format!(":{p}")).unwrap_or_default(),
                );
                format!("{origin}{}", self.metadata_path())
            }
            Err(_) => self.metadata_path(),
        }
    }

    /// The RFC 9728 §5.1 challenge. Handing this back on an unauthenticated
    /// request is what lets an MCP client find the authorization server
    /// without being configured with it.
    pub fn challenge(&self, error: Option<(&str, &str)>) -> String {
        let metadata = self.metadata_url();
        match error {
            Some((code, description)) => format!(
                "Bearer resource_metadata=\"{metadata}\", error=\"{code}\", \
                 error_description=\"{}\"",
                description.replace('"', "'")
            ),
            None => format!("Bearer resource_metadata=\"{metadata}\""),
        }
    }

    /// Verifies a bearer token: signature against cached JWKS, `iss`, `aud`,
    /// `exp`, and nothing else. Scope checking is the caller's, because what
    /// a given route requires is not something this type can know.
    pub async fn verify(&self, token: &str) -> Result<ResourceClaims, Response> {
        let unauthorized = |code: &str, description: &str| {
            let mut response = (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": code, "error_description": description })),
            )
                .into_response();
            if let Ok(value) = self.challenge(Some((code, description))).parse() {
                response
                    .headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, value);
            }
            response
        };

        let keys = self.jwks_keys().await.map_err(|e| {
            tracing::warn!(error = %e, "failed to fetch JWKS from the authorization server");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "temporarily_unavailable" })),
            )
                .into_response()
        })?;

        let header = jsonwebtoken::decode_header(token)
            .map_err(|_| unauthorized("invalid_token", "malformed access token"))?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[self.config.issuer.trim_end_matches('/')]);
        validation.set_audience(&[self.config.resource_uri.trim_end_matches('/')]);

        let candidates = keys.iter().filter(|k| match (&header.kid, k.get("kid")) {
            (Some(kid), Some(key_kid)) => key_kid.as_str() == Some(kid.as_str()),
            _ => true,
        });

        for key in candidates {
            let (Some(x), Some(y)) = (
                key.get("x").and_then(|v| v.as_str()),
                key.get("y").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            let Ok(decoding) = DecodingKey::from_ec_components(x, y) else {
                continue;
            };
            if let Ok(data) =
                jsonwebtoken::decode::<ResourceClaims>(token, &decoding, &validation)
            {
                return Ok(data.claims);
            }
        }

        Err(unauthorized(
            "invalid_token",
            "the access token is expired, malformed, issued by another issuer, or minted for a \
             different resource",
        ))
    }

    async fn jwks_keys(&self) -> Result<Arc<Vec<serde_json::Value>>, anyhow::Error> {
        if let Some(keys) = self.jwks.get(&()).await {
            return Ok(keys);
        }

        // The metadata document is the indirection: the JWKS URI is read from
        // it rather than assumed, so the AS can move the path.
        let metadata_url = format!(
            "{}/.well-known/oauth-authorization-server",
            self.config.issuer.trim_end_matches('/')
        );
        let metadata: serde_json::Value = self
            .client
            .get(&metadata_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let jwks_uri = metadata
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("authorization server metadata has no jwks_uri"))?;

        let jwks: serde_json::Value = self
            .client
            .get(jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let keys: Vec<serde_json::Value> = jwks
            .get("keys")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let keys = Arc::new(keys);
        self.jwks.insert((), Arc::clone(&keys)).await;
        Ok(keys)
    }
}

async fn protected_resource_metadata(State(server): State<Arc<ResourceServer>>) -> Response {
    Json(json!({
        "resource": server.config.resource_uri.trim_end_matches('/'),
        "authorization_servers": [server.config.issuer.trim_end_matches('/')],
        "scopes_supported": server.config.required_scopes,
        "bearer_methods_supported": ["header"],
    }))
    .into_response()
}

/// The state a route guard carries: the server plus the scopes *this* route
/// requires. Separate from `ResourceServerConfig::required_scopes`, which is
/// the floor for every guarded route.
#[derive(Clone)]
pub struct ScopeGuard {
    server: Arc<ResourceServer>,
    scopes: Arc<Vec<String>>,
}

impl ScopeGuard {
    pub fn new<I, S>(server: &Arc<ResourceServer>, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            server: Arc::clone(server),
            scopes: Arc::new(scopes.into_iter().map(Into::into).collect()),
        }
    }
}

/// Middleware: validates the bearer token and the scopes this route needs,
/// then puts the verified [`ResourceClaims`] into request extensions where
/// the handler can pick them up with the [`AccessToken`] extractor.
///
/// Use with `axum::middleware::from_fn_with_state(ScopeGuard::new(…), require_scope)`,
/// layered over the protected routes **only** — never over
/// [`ResourceServer::router`], which serves the metadata document a client
/// must be able to fetch without a token.
pub async fn require_scope(
    State(guard): State<ScopeGuard>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(token) = bearer(request.headers()) else {
        // No credentials at all is the discovery case: the challenge tells
        // the client where to go authorize.
        let mut response = (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_request", "error_description": "a bearer token is required" })),
        )
            .into_response();
        if let Ok(value) = guard.server.challenge(None).parse() {
            response
                .headers_mut()
                .insert(axum::http::header::WWW_AUTHENTICATE, value);
        }
        return response;
    };

    let claims = match guard.server.verify(token).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };

    let required = guard
        .server
        .config
        .required_scopes
        .iter()
        .chain(guard.scopes.iter());

    for scope in required {
        if !claims.has_scope(scope) {
            let description = format!("this token does not carry the `{scope}` scope");
            let mut response = (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "insufficient_scope",
                    "error_description": description,
                })),
            )
                .into_response();
            if let Ok(value) = guard
                .server
                .challenge(Some(("insufficient_scope", &description)))
                .parse()
            {
                response
                    .headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, value);
            }
            return response;
        }
    }

    request.extensions_mut().insert(claims);
    next.run(request).await
}

/// Handler extractor for the claims [`require_scope`] verified. Rejects with
/// 500 rather than 401 when absent: reaching a handler without the guard in
/// front of it is a wiring mistake in the service, not a client error.
pub struct AccessToken(pub ResourceClaims);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for AccessToken {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ResourceClaims>()
            .cloned()
            .map(AccessToken)
            .ok_or_else(|| {
                tracing::error!(
                    "AccessToken was extracted on a route with no require_scope guard in front \
                     of it; the request was not authenticated"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "misconfigured_resource_server" })),
                )
                    .into_response()
            })
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(scope: &str) -> ResourceClaims {
        ResourceClaims {
            iss: "https://auth.example".into(),
            sub: "00000000-0000-0000-0000-000000000001".into(),
            aud: "https://rs.example/mcp".into(),
            client_id: "aeg_cid_x".into(),
            scope: scope.into(),
            sid: "00000000-0000-0000-0000-000000000002".into(),
            jti: "j".into(),
            iat: 0,
            exp: 0,
        }
    }

    #[test]
    fn scope_matching_is_whole_token_not_substring() {
        let c = claims("mcp:read mcp:write");
        assert!(c.has_scope("mcp:read"));
        assert!(c.has_scope("mcp:write"));
        assert!(!c.has_scope("mcp"));
        assert!(!c.has_scope("read"));
        assert!(!c.has_scope("mcp:admin"));
    }

    /// The challenge is the discovery mechanism, so its shape is a contract:
    /// a client that cannot find `resource_metadata` in it cannot find the
    /// authorization server at all.
    #[test]
    fn the_challenge_points_at_the_metadata_document() {
        let server = ResourceServer::new(ResourceServerConfig {
            issuer: "https://auth.example/".into(),
            resource_uri: "https://rs.example/mcp/".into(),
            required_scopes: vec!["mcp:read".into()],
            jwks_cache_ttl: Duration::from_secs(60),
        })
        .unwrap();

        assert_eq!(server.metadata_path(), "/.well-known/oauth-protected-resource/mcp");
        assert_eq!(
            server.challenge(None),
            "Bearer resource_metadata=\"https://rs.example/.well-known/oauth-protected-resource/mcp\""
        );
        assert!(server
            .challenge(Some(("invalid_token", "expired")))
            .contains("error=\"invalid_token\""));
    }
}
