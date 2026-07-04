use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::types::AuthError;

pub struct RateLimiter {
    windows: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(
        &self,
        key: &str,
        window: Duration,
        max_attempts: u32,
    ) -> Result<(), AuthError> {
        let mut windows = self.windows.lock().unwrap();
        let now = Instant::now();
        let cutoff = now - window;

        let entries = windows.entry(key.to_string()).or_default();
        entries.retain(|t| *t > cutoff);

        if entries.len() >= max_attempts as usize {
            let oldest = entries.first().copied().unwrap_or(now);
            let retry_after = window.saturating_sub(now.duration_since(oldest));
            return Err(AuthError::RateLimited { retry_after });
        }

        entries.push(now);
        Ok(())
    }

    pub fn check_auth(&self, ip: Option<IpAddr>, username: &str, config: &super::RateLimitConfig) -> Result<(), AuthError> {
        if let Some(ip) = ip {
            self.check(
                &format!("auth:ip:{ip}"),
                config.auth_window,
                config.auth_max_attempts,
            )?;
        }
        self.check(
            &format!("auth:user:{username}"),
            config.auth_window,
            config.auth_max_attempts,
        )
    }

    pub fn check_register(&self, ip: Option<IpAddr>, config: &super::RateLimitConfig) -> Result<(), AuthError> {
        if let Some(ip) = ip {
            self.check(
                &format!("register:ip:{ip}"),
                config.register_window,
                config.register_max_attempts,
            )?;
        }
        Ok(())
    }
}
