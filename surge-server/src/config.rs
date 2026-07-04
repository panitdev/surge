use std::collections::HashMap;
use std::time::Duration;

use secrecy::SecretString;
use surge_engine::{EngineConfig, PepperConfig, RateLimitConfig};

pub struct ServerConfig {
    pub database_url: SecretString,
    pub pepper: SecretString,
    pub bind_addr: String,
    pub cookie_domain: String,
    pub auth_ui_origin: String,
    pub session_ttl_hours: u64,
    pub registration: RegistrationMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationMode {
    Open,
    Invite,
    Closed,
}

impl ServerConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = SecretString::from(
            std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/surge".to_string()),
        );
        let pepper = SecretString::from(
            std::env::var("SURGE_PEPPER").unwrap_or_else(|_| "dev-pepper-change-me".to_string()),
        );
        let bind_addr =
            std::env::var("SURGE_BIND").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
        let cookie_domain =
            std::env::var("SURGE_COOKIE_DOMAIN").unwrap_or_else(|_| ".panit.dev".to_string());
        let auth_ui_origin = std::env::var("SURGE_AUTH_UI_ORIGIN")
            .unwrap_or_else(|_| "https://auth.panit.dev".to_string());
        let session_ttl_hours: u64 = std::env::var("SURGE_SESSION_TTL_HOURS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(72);
        let registration = match std::env::var("SURGE_REGISTRATION")
            .unwrap_or_else(|_| "open".to_string())
            .as_str()
        {
            "invite" => RegistrationMode::Invite,
            "closed" => RegistrationMode::Closed,
            _ => RegistrationMode::Open,
        };

        Ok(Self {
            database_url,
            pepper,
            bind_addr,
            cookie_domain,
            auth_ui_origin,
            session_ttl_hours,
            registration,
        })
    }

    pub fn engine_config(&self) -> anyhow::Result<EngineConfig> {
        let mut peppers = HashMap::new();
        peppers.insert(1u8, self.pepper.clone());

        Ok(EngineConfig {
            database_url: self.database_url.clone(),
            pepper: PepperConfig {
                current_version: 1,
                peppers,
            },
            session_ttl: Duration::from_secs(self.session_ttl_hours * 3600),
            rate_limit: RateLimitConfig::default(),
        })
    }

    pub fn session_ttl(&self) -> Duration {
        Duration::from_secs(self.session_ttl_hours * 3600)
    }
}
