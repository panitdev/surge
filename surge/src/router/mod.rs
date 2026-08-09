//! The mountable browser router (the perimeter). Owns `RateLimiter`
//! policy, CORS zoning, cookie/CSRF, and background maintenance — none of
//! which the trusted `AuthProvider` surface carries itself.

mod browser;
mod cookie;
mod cors;
mod csrf;
mod error;
mod oauth_bridge;
mod proxy;
pub mod rate_limit;
mod trusted_proxy;

pub use browser::{BrowserRouterConfig, FactorPolicy, RegistrationMode};
pub use browser::{spawn_maintenance, DEFAULT_MAINTENANCE_INTERVAL};
pub(crate) use browser::embedded_browser_router;
pub(crate) use proxy::{proxy_browser_router, ProxyConfig};
pub use oauth_bridge::OauthBridgeConfig;
pub use rate_limit::{PostgresRateLimiter, RateLimitConfig, RateLimitPolicy, RateLimiter};
