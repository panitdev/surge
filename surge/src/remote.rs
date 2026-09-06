use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use tracing::{error, warn};
use url::Url;

use crate::traits::AuthProvider;
use crate::*;

pub struct RemoteConfig {
    pub base_url: Url,
    pub service_token: SecretString,
    pub cache_ttl: Duration,
    pub cache_max_entries: u64,
    pub timeout: Duration,
}

pub struct RemoteProvider {
    client: Client,
    base_url: Url,
    service_token: SecretString,
    cache: Cache<Vec<u8>, Session>,
}

impl RemoteProvider {
    pub fn new(config: RemoteConfig) -> Result<Self, anyhow::Error> {
        // Redirects are never this client's to resolve. It serves two callers, and
        // following breaks one of them badly: `browser_router`'s proxy exists to hand
        // upstream's response back to the browser, and upstream answers `GET /v1/login`
        // with a 303 to the auth UI. Followed here, the browser instead receives that
        // page's HTML under *this* service's origin — root-relative assets 404, and the
        // `flow` id, which only ever lived in the `Location` header, is lost. The
        // service-token API calls are the other caller; they expect JSON and have no
        // redirect to follow.
        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let cache = Cache::builder()
            .max_capacity(config.cache_max_entries)
            .time_to_live(config.cache_ttl)
            .build();

        Ok(Self {
            client,
            base_url: config.base_url,
            service_token: config.service_token,
            cache,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url.as_str().trim_end_matches('/'))
    }

    fn authed(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, self.url(path))
            .bearer_auth(self.service_token.expose_secret())
    }

    fn map_error(status: reqwest::StatusCode, body: &serde_json::Value) -> AuthError {
        let error_code = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
        let err: AuthError = match error_code {
            "invalid_token" => AuthError::InvalidToken,
            "session_expired" => AuthError::SessionExpired,
            "identity_disabled" => AuthError::IdentityDisabled,
            "invalid_credentials" => AuthError::InvalidCredentials,
            "username_taken" => AuthError::UsernameTaken,
            "not_found" => AuthError::NotFound,
            "forbidden" => AuthError::Forbidden,
            "scope_not_granted" => AuthError::ScopeNotGranted,
            "rate_limited" => AuthError::RateLimited {
                retry_after: Duration::from_secs(
                    body.get("retry_after")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(60),
                ),
            },
            _ if status.is_server_error() => AuthError::Unavailable,
            _ => AuthError::Internal(anyhow::anyhow!("unexpected error: {status} {body}")),
        };
        if matches!(err, AuthError::Unavailable | AuthError::Internal(_)) {
            warn!(
                status = %status.as_u16(),
                error_code,
                body = %body,
                "surge server returned error"
            );
        }
        err
    }

    fn token_cache_key(token: &SessionToken) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(token.expose_secret().as_bytes());
        hasher.finalize().to_vec()
    }

    fn map_reqwest_err(e: reqwest::Error) -> AuthError {
        if e.is_timeout() {
            warn!(error = %e, "surge server request timed out");
            AuthError::Timeout
        } else {
            error!(error = %e, "surge server unreachable");
            AuthError::Unavailable
        }
    }

    async fn parse_or_error<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> Result<T, AuthError> {
        let status = resp.status();
        if status.is_success() {
            resp.json().await.map_err(|e| AuthError::Internal(e.into()))
        } else {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            Err(Self::map_error(status, &body))
        }
    }

    async fn parse_issued_session(resp: reqwest::Response) -> Result<IssuedSession, AuthError> {
        #[derive(serde::Deserialize)]
        struct IssuedSessionResponse {
            session: Session,
            token: String,
        }

        let body: IssuedSessionResponse = Self::parse_or_error(resp).await?;
        let token = SessionToken::from_raw(&body.token)
            .ok_or_else(|| AuthError::Internal(anyhow::anyhow!("server returned invalid token")))?;
        Ok(IssuedSession::new(body.session, token))
    }

    async fn parse_link_auth(resp: reqwest::Response) -> Result<LinkAuth, AuthError> {
        #[derive(serde::Deserialize)]
        struct LinkAuthResponse {
            session: Session,
            token: String,
            created: bool,
        }

        let body: LinkAuthResponse = Self::parse_or_error(resp).await?;
        let token = SessionToken::from_raw(&body.token)
            .ok_or_else(|| AuthError::Internal(anyhow::anyhow!("server returned invalid token")))?;
        Ok(LinkAuth::new(
            IssuedSession::new(body.session, token),
            body.created,
        ))
    }
}

#[async_trait]
impl AuthProvider for RemoteProvider {
    async fn verify_session(&self, token: Option<SessionToken>) -> Result<Session, AuthError> {
        let token = token.ok_or(AuthError::InvalidToken)?;
        let cache_key = Self::token_cache_key(&token);

        if let Some(session) = self.cache.get(&cache_key).await {
            return Ok(session);
        }

        let resp = self
            .authed(reqwest::Method::POST, "/v1/sessions/verify")
            .json(&serde_json::json!({ "token": token.expose_secret() }))
            .send()
            .await
            .map_err(Self::map_reqwest_err)?;

        let session: Session = Self::parse_or_error(resp).await?;
        self.cache.insert(cache_key, session.clone()).await;
        Ok(session)
    }

    async fn revoke_session(&self, token: &SessionToken) -> Result<(), AuthError> {
        let cache_key = Self::token_cache_key(token);
        self.cache.invalidate(&cache_key).await;

        let resp = self
            .authed(reqwest::Method::POST, "/v1/sessions/revoke")
            .json(&serde_json::json!({ "token": token.expose_secret() }))
            .send()
            .await
            .map_err(Self::map_reqwest_err)?;

        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            Err(Self::map_error(status, &body))
        }
    }

    async fn revoke_all_sessions(&self, id: IdentityId) -> Result<u64, AuthError> {
        let resp = self
            .authed(
                reqwest::Method::POST,
                &format!("/v1/identities/{id}/revoke-sessions"),
            )
            .send()
            .await
            .map_err(Self::map_reqwest_err)?;

        let body: serde_json::Value = Self::parse_or_error(resp).await?;
        Ok(body.get("revoked").and_then(|v| v.as_u64()).unwrap_or(0))
    }

    async fn identity(&self, id: IdentityId) -> Result<Identity, AuthError> {
        let resp = self
            .authed(reqwest::Method::GET, &format!("/v1/identities/{id}"))
            .send()
            .await
            .map_err(Self::map_reqwest_err)?;

        Self::parse_or_error(resp).await
    }

    async fn identity_by_username(&self, username: &Username) -> Result<Identity, AuthError> {
        let resp = self
            .authed(reqwest::Method::GET, "/v1/identities")
            .query(&[("username", username.as_str())])
            .send()
            .await
            .map_err(Self::map_reqwest_err)?;

        Self::parse_or_error(resp).await
    }

    async fn update_profile(
        &self,
        id: IdentityId,
        patch: ProfilePatch,
    ) -> Result<Identity, AuthError> {
        let resp = self
            .authed(
                reqwest::Method::PATCH,
                &format!("/v1/identities/{id}/profile"),
            )
            .json(&patch)
            .send()
            .await
            .map_err(Self::map_reqwest_err)?;

        Self::parse_or_error(resp).await
    }

    async fn register(&self, req: RegisterRequest) -> Result<Identity, AuthError> {
        let resp = self
            .authed(reqwest::Method::POST, "/v1/register")
            .json(&serde_json::json!({
                "username": req.username.as_str(),
                "password": req.password.expose(),
                "display_name": req.display_name,
            }))
            .send()
            .await
            .map_err(Self::map_reqwest_err)?;

        Self::parse_or_error(resp).await
    }

    async fn register_and_authenticate(
        &self,
        req: RegisterRequest,
    ) -> Result<IssuedSession, AuthError> {
        let resp = self
            .authed(reqwest::Method::POST, "/v1/register-and-authenticate")
            .json(&serde_json::json!({
                "username": req.username.as_str(),
                "password": req.password.expose(),
                "display_name": req.display_name,
            }))
            .send()
            .await
            .map_err(Self::map_reqwest_err)?;

        Self::parse_issued_session(resp).await
    }

    async fn authenticate_password(
        &self,
        username: &Username,
        password: &Password,
    ) -> Result<IssuedSession, AuthError> {
        let resp = self
            .authed(reqwest::Method::POST, "/v1/authenticate/password")
            .json(&serde_json::json!({
                "username": username.as_str(),
                "password": password.expose(),
            }))
            .send()
            .await
            .map_err(Self::map_reqwest_err)?;

        Self::parse_issued_session(resp).await
    }

    async fn authenticate_by_link(
        &self,
        provider: &str,
        subject: &str,
        seed: &LinkSeed,
    ) -> Result<LinkAuth, AuthError> {
        let resp = self
            .authed(reqwest::Method::POST, "/v1/authenticate/link")
            .json(&serde_json::json!({
                "provider": provider,
                "subject": subject,
                "seed": {
                    "username": seed.username.as_str(),
                    "display_name": seed.display_name,
                },
            }))
            .send()
            .await
            .map_err(Self::map_reqwest_err)?;

        Self::parse_link_auth(resp).await
    }

    async fn link_identity(
        &self,
        identity_id: IdentityId,
        provider: &str,
        subject: &str,
        verified: bool,
    ) -> Result<IdentityLink, AuthError> {
        let resp = self
            .authed(
                reqwest::Method::POST,
                &format!("/v1/identities/{identity_id}/links"),
            )
            .json(&serde_json::json!({
                "provider": provider,
                "subject": subject,
                "verified": verified,
            }))
            .send()
            .await
            .map_err(Self::map_reqwest_err)?;

        Self::parse_or_error(resp).await
    }

    async fn identity_links(&self, identity_id: IdentityId) -> Result<Vec<IdentityLink>, AuthError> {
        let resp = self
            .authed(
                reqwest::Method::GET,
                &format!("/v1/identities/{identity_id}/links"),
            )
            .send()
            .await
            .map_err(Self::map_reqwest_err)?;

        Self::parse_or_error(resp).await
    }

    async fn unlink_identity(
        &self,
        identity_id: IdentityId,
        provider: &str,
        subject: &str,
    ) -> Result<(), AuthError> {
        let resp = self
            .authed(
                reqwest::Method::DELETE,
                &format!("/v1/identities/{identity_id}/links"),
            )
            .json(&serde_json::json!({
                "provider": provider,
                "subject": subject,
            }))
            .send()
            .await
            .map_err(Self::map_reqwest_err)?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        Err(Self::map_error(status, &body))
    }

    #[cfg(feature = "router")]
    fn browser_router(
        self: std::sync::Arc<Self>,
        config: crate::router::BrowserRouterConfig,
    ) -> axum::Router {
        // An authorization server has exactly one issuer identity, so this is
        // the one browser route a service must never proxy. A service
        // answering `/oauth2/token` on its own origin would be minting tokens
        // under central's `iss`; the client-side issuer check would then fail
        // quietly, in ways that look like clock skew. Warn and ignore.
        #[cfg(feature = "oauth-as")]
        if config.oauth_as.is_some() {
            tracing::warn!(
                "oauth_as is set on a RemoteProvider and is being ignored: the OAuth \
                 authorization server is mounted by central only (internal/oauth-as.md §2)"
            );
        }

        crate::router::proxy_browser_router(crate::router::ProxyConfig {
            upstream_base_url: self.base_url.clone(),
            cookie_domain: config.cookie_domain,
            auth_ui_origin: config.auth_ui_origin,
            session_cors_origins: config.session_cors_origins,
            service_token: self.service_token.clone(),
            client: self.client.clone(),
        })
    }
}
