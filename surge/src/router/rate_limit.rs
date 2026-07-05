use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use surge_engine::Engine;

use crate::AuthError;

/// Perimeter policy: composes the key from `(scope, action, ip|username)`
/// and decides the verdict. Sits in front of the engine's neutral counter
/// store, which knows nothing about IPs, actions, or thresholds.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn check(
        &self,
        scope: &str,
        action: &str,
        ip: Option<IpAddr>,
        username: Option<&str>,
    ) -> Result<(), AuthError>;
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimitPolicy {
    pub window: Duration,
    pub max_attempts: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    pub authenticate: RateLimitPolicy,
    pub register: RateLimitPolicy,
    pub flow_submit: RateLimitPolicy,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            authenticate: RateLimitPolicy {
                window: Duration::from_secs(900),
                max_attempts: 10,
            },
            register: RateLimitPolicy {
                window: Duration::from_secs(3600),
                max_attempts: 5,
            },
            flow_submit: RateLimitPolicy {
                window: Duration::from_secs(600),
                max_attempts: 20,
            },
        }
    }
}

/// Postgres-backed `RateLimiter` over `Engine::bump_and_count`
/// (`surge.rate_limit_window`), sharing the same pool as the provider it
/// stands in front of. Fixed-window bucketing; backoff via `retry_after`,
/// not a hard lockout. `(ip)` and `(username)` are bumped and checked
/// independently, so either alone can trip the limit.
pub struct PostgresRateLimiter {
    engine: Arc<Engine>,
    config: RateLimitConfig,
}

impl PostgresRateLimiter {
    pub fn new(engine: Arc<Engine>, config: RateLimitConfig) -> Self {
        Self { engine, config }
    }

    fn policy_for(&self, action: &str) -> Option<&RateLimitPolicy> {
        match action {
            "authenticate" => Some(&self.config.authenticate),
            "register" => Some(&self.config.register),
            "flow_submit" => Some(&self.config.flow_submit),
            _ => None,
        }
    }

    async fn bump(&self, key: &str, policy: &RateLimitPolicy) -> Result<(), AuthError> {
        let window_count = self.engine.bump_and_count(key, policy.window).await?;
        if window_count.count > policy.max_attempts {
            let elapsed = chrono::Utc::now()
                .signed_duration_since(window_count.window_start)
                .to_std()
                .unwrap_or_default();
            let retry_after = policy.window.saturating_sub(elapsed);
            return Err(AuthError::RateLimited { retry_after });
        }
        Ok(())
    }
}

#[async_trait]
impl RateLimiter for PostgresRateLimiter {
    async fn check(
        &self,
        scope: &str,
        action: &str,
        ip: Option<IpAddr>,
        username: Option<&str>,
    ) -> Result<(), AuthError> {
        let Some(policy) = self.policy_for(action) else {
            return Ok(());
        };

        if let Some(ip) = ip {
            self.bump(&format!("{scope}|{action}|ip|{ip}"), policy).await?;
        }
        if let Some(username) = username {
            self.bump(&format!("{scope}|{action}|user|{username}"), policy)
                .await?;
        }
        Ok(())
    }
}
