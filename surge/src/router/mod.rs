//! The mountable browser router (the perimeter). Owns `RateLimiter`
//! policy, CORS zoning, cookie/CSRF, and background maintenance — none of
//! which the trusted `AuthProvider` surface carries itself.

mod browser;
mod cookie;
mod cors;
mod csrf;
mod error;
#[cfg(feature = "oauth-as")]
mod oauth_as;
mod proxy;
pub mod rate_limit;
#[cfg(feature = "test-provider")]
mod test;
mod trusted_proxy;

pub use browser::{BrowserRouterConfig, FactorPolicy, RegistrationMode};
pub use browser::{spawn_maintenance, DEFAULT_MAINTENANCE_INTERVAL};
pub(crate) use browser::embedded_browser_router;
pub(crate) use proxy::{proxy_browser_router, ProxyConfig};
#[cfg(feature = "test-provider")]
pub(crate) use test::test_browser_router;
#[cfg(feature = "oauth-as")]
pub use oauth_as::{
    is_public_ip, CimdDocumentFetcher, CimdError, CimdLimits, CimdResolver, FetchError,
    FetchedDocument, HttpDocumentFetcher, OauthAsConfig,
};
pub use rate_limit::{PostgresRateLimiter, RateLimitConfig, RateLimitPolicy, RateLimiter};

async fn no_store(mut response: axum::response::Response) -> axum::response::Response {
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(all(test, feature = "embedded"))]
mod account_list_tests;
