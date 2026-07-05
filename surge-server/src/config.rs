use std::time::Duration;

use secrecy::SecretString;
use surge::router::RegistrationMode;
use surge::EmbeddedConfig;

pub struct ServerConfig {
    pub database_url: SecretString,
    pub pepper: SecretString,
    pub bind_addr: String,
    pub cookie_domain: String,
    pub auth_ui_origin: String,
    pub session_ttl_hours: u64,
    pub registration: RegistrationMode,
    /// Non-empty enables the opt-in browser->Surge session-management CORS
    /// zone (credentialed, over this union). Empty keeps the narrow,
    /// same-origin-only default.
    pub session_cors_origins: Vec<String>,
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
        let session_cors_origins = std::env::var("SURGE_SESSION_CORS_ORIGINS")
            .ok()
            .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();

        Ok(Self {
            database_url,
            pepper,
            bind_addr,
            cookie_domain,
            auth_ui_origin,
            session_ttl_hours,
            registration,
            session_cors_origins,
        })
    }

    pub fn embedded_config(&self) -> EmbeddedConfig {
        EmbeddedConfig {
            database_url: self.database_url.clone(),
            pepper: self.pepper.clone(),
            session_ttl: self.session_ttl(),
        }
    }

    pub fn session_ttl(&self) -> Duration {
        Duration::from_secs(self.session_ttl_hours * 3600)
    }
}
