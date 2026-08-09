//! Trust boundary for the reverse-proxied browser perimeter.
//!
//! A `RemoteProvider` mounts a proxy in front of this router, so every
//! browser request central sees arrives from the *service's* IP, not the
//! end user's. Rate limiting keyed on the peer address would then collapse
//! the whole service's user base into one bucket (`authenticate` is
//! 10/15min per IP — a handful of failed logins would lock everyone out).
//!
//! The proxy therefore states the end user's address in
//! `X-Surge-Client-Ip`, and proves it may do so with a service token in
//! `X-Surge-Service-Token` carrying the `browser_proxy` grant. A claim
//! without a valid token is rejected outright rather than ignored, so a
//! browser cannot spoof its way out of a rate-limit bucket.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use moka::future::Cache;
use serde_json::json;
use sha2::{Digest, Sha256};
use surge_engine::Engine;
use tracing::warn;

/// States the end user's IP address on a proxied browser request.
pub(crate) const CLIENT_IP_HEADER: &str = "x-surge-client-ip";
/// Proves the sender may make that statement.
pub(crate) const SERVICE_TOKEN_HEADER: &str = "x-surge-service-token";

/// Grant a service token needs to front the browser perimeter.
pub(crate) const BROWSER_PROXY_GRANT: &str = "browser_proxy";

/// Verifying a service token is a DB round-trip, and the browser
/// perimeter is chatty (`/whoami` on every page load). Revocation is
/// visible within this window.
const TOKEN_CACHE_TTL: Duration = Duration::from_secs(60);

/// The end user's address, as stated by an authenticated proxy. Present
/// only when the trusted-proxy middleware verified the statement.
#[derive(Clone, Copy)]
pub(crate) struct TrustedClientIp(pub std::net::IpAddr);

pub(crate) struct TrustedProxyState {
    engine: Arc<Engine>,
    /// token hash -> whether it carries `browser_proxy`. Absent means
    /// "not looked up yet", not "invalid" — invalid tokens are cached as
    /// `false` too, so a token-guessing loop still costs one lookup per
    /// distinct token rather than one per request.
    verdicts: Cache<Vec<u8>, bool>,
}

impl TrustedProxyState {
    pub(crate) fn new(engine: Arc<Engine>) -> Self {
        Self {
            engine,
            verdicts: Cache::builder()
                .max_capacity(1024)
                .time_to_live(TOKEN_CACHE_TTL)
                .build(),
        }
    }

    async fn is_trusted_proxy(&self, token: &str) -> bool {
        let hash = Sha256::digest(token.as_bytes()).to_vec();

        if let Some(verdict) = self.verdicts.get(&hash).await {
            return verdict;
        }

        let verdict = match self.engine.verify_service_token(&hash).await {
            Ok(svc) => svc.grants.iter().any(|g| g == BROWSER_PROXY_GRANT),
            Err(_) => false,
        };
        self.verdicts.insert(hash, verdict).await;
        verdict
    }
}

/// Resolves proxy claims before any handler runs, and strips both headers
/// so nothing downstream can mistake an unverified claim for a verified
/// one.
pub(crate) async fn trusted_proxy(
    State(state): State<Arc<TrustedProxyState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let claimed_ip = take_header(&mut req, CLIENT_IP_HEADER);
    let token = take_header(&mut req, SERVICE_TOKEN_HEADER);

    if claimed_ip.is_none() && token.is_none() {
        return next.run(req).await;
    }

    let Some(token) = token else {
        // An IP claim with nothing backing it: refuse rather than ignore.
        // Ignoring would silently rate-limit the caller under the wrong
        // key, which is exactly the failure this header exists to avoid.
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "missing_service_token"})),
        )
            .into_response();
    };

    if !state.is_trusted_proxy(&token).await {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "forbidden",
                "message": format!("service token is missing the `{BROWSER_PROXY_GRANT}` grant"),
            })),
        )
            .into_response();
    }

    match claimed_ip.as_deref().map(str::parse) {
        Some(Ok(ip)) => {
            req.extensions_mut().insert(TrustedClientIp(ip));
        }
        Some(Err(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "message": format!("`{CLIENT_IP_HEADER}` is not an IP address"),
                })),
            )
                .into_response();
        }
        // Authenticated but silent about the end user: the proxy could not
        // determine one. Rate limiting falls back to the peer address,
        // which for a proxy is the whole service — worth saying out loud.
        None => warn!(
            "trusted proxy sent no {CLIENT_IP_HEADER}; rate limiting this \
             request against the proxy's own address"
        ),
    }

    next.run(req).await
}

fn take_header(req: &mut Request, name: &str) -> Option<String> {
    let value = req.headers_mut().remove(name)?;
    value.to_str().ok().map(str::to_owned)
}
