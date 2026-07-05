//! The mountable browser router (the perimeter). Owns `RateLimiter`
//! policy, CORS zoning, cookie/CSRF, and background maintenance — none of
//! which the trusted `AuthProvider` surface carries itself.

mod browser;
mod cookie;
mod cors;
mod csrf;
mod error;
pub mod rate_limit;

pub use browser::{browser, BrowserRouter, BrowserRouterConfig, RegistrationMode};
pub use rate_limit::{PostgresRateLimiter, RateLimitConfig, RateLimitPolicy, RateLimiter};
