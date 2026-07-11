//! Ory Hydra admin-API client. The only module in this crate aware of
//! Hydra's wire format — see `router::oauth_bridge`, which depends on this
//! module but never the reverse. Per rfc.md, Hydra remains the OAuth 2.1
//! authorization server; this is the thin admin-API seam the login/consent
//! bridge calls into.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum HydraError {
    #[error("hydra admin request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("hydra admin error ({status}): {error}{}", description.as_deref().map(|d| format!(" ({d})")).unwrap_or_default())]
    Api {
        status: u16,
        error: String,
        description: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
struct HydraErrorBody {
    error: String,
    error_description: Option<String>,
}

#[derive(Serialize)]
struct AcceptLoginRequest<'a> {
    subject: &'a str,
}

#[derive(Serialize)]
struct AcceptConsentRequest<'a> {
    grant_scope: &'a [String],
    grant_access_token_audience: &'a [String],
    remember: bool,
}

#[derive(Deserialize)]
struct RedirectResponse {
    redirect_to: String,
}

#[derive(Deserialize)]
struct ConsentRequestInfo {
    #[serde(default)]
    requested_scope: Vec<String>,
    #[serde(default)]
    requested_access_token_audience: Vec<String>,
}

pub struct HydraAdmin {
    client: reqwest::Client,
    base_url: Url,
}

impl HydraAdmin {
    pub fn new(base_url: Url, timeout: Duration) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder().timeout(timeout).build()?;
        Ok(Self { client, base_url })
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> Result<T, HydraError> {
        let status = resp.status();
        if status.is_success() {
            Ok(resp.json::<T>().await?)
        } else {
            let body = resp.json::<HydraErrorBody>().await.unwrap_or(HydraErrorBody {
                error: "unknown_error".into(),
                error_description: None,
            });
            Err(HydraError::Api {
                status: status.as_u16(),
                error: body.error,
                description: body.error_description,
            })
        }
    }

    /// Accepts a login challenge for the given stable subject identifier
    /// (the internal identity ID). Returns the URL Hydra wants the browser
    /// redirected to next.
    pub async fn accept_login(&self, challenge: &str, subject: &str) -> Result<String, HydraError> {
        let url = self
            .base_url
            .join("/admin/oauth2/auth/requests/login/accept")
            .expect("static admin path");

        let resp = self
            .client
            .put(url)
            .query(&[("login_challenge", challenge)])
            .json(&AcceptLoginRequest { subject })
            .send()
            .await?;

        let body: RedirectResponse = Self::handle_response(resp).await?;
        Ok(body.redirect_to)
    }

    /// Accepts a consent challenge without rendering a screen (first-party
    /// clients only — see rfc.md's non-goals). Hydra requires the granted
    /// scope/audience to be echoed back even when consent UI is skipped, so
    /// this first fetches the requested scope before accepting.
    pub async fn skip_consent(&self, challenge: &str) -> Result<String, HydraError> {
        let get_url = self
            .base_url
            .join("/admin/oauth2/auth/requests/consent")
            .expect("static admin path");

        let resp = self
            .client
            .get(get_url)
            .query(&[("consent_challenge", challenge)])
            .send()
            .await?;
        let info: ConsentRequestInfo = Self::handle_response(resp).await?;

        let accept_url = self
            .base_url
            .join("/admin/oauth2/auth/requests/consent/accept")
            .expect("static admin path");

        let resp = self
            .client
            .put(accept_url)
            .query(&[("consent_challenge", challenge)])
            .json(&AcceptConsentRequest {
                grant_scope: &info.requested_scope,
                grant_access_token_audience: &info.requested_access_token_audience,
                remember: false,
            })
            .send()
            .await?;

        let body: RedirectResponse = Self::handle_response(resp).await?;
        Ok(body.redirect_to)
    }
}
