use std::time::Duration;

use secrecy::SecretString;
use surge::router::{FactorPolicy, RegistrationMode};
use surge::EmbeddedConfig;

pub struct ServerConfig {
    pub database_url: SecretString,
    pub pepper: SecretString,
    pub bind_addr: String,
    pub cookie_domain: String,
    pub auth_ui_origin: String,
    pub session_ttl_hours: u64,
    pub registration: RegistrationMode,
    /// Soft, server-wide factor-enrollment recommendation (`SURGE_FACTOR_POLICY`).
    /// Never blocks login/registration; surfaced to the frontend so it can
    /// prompt for enrollment.
    pub factor_policy: FactorPolicy,
    /// Non-empty enables the opt-in browser->Surge session-management CORS
    /// zone (credentialed, over this union). Empty keeps the narrow,
    /// same-origin-only default.
    pub session_cors_origins: Vec<String>,
    /// Explicit operator acknowledgment of served+inline (architecture.md
    /// §6): this deployment is served (standalone, not embedded), so
    /// enabling content-negotiated flow-init on `GET /login` means
    /// credential entry gets proxied through a consuming service's origin.
    /// Defaults to `false` — a served deployment stays redirect-only until
    /// this is set.
    pub allow_served_inline: bool,
    /// Opt-in Hydra login/consent bridge (rfc.md). `None` unless
    /// `SURGE_HYDRA_ADMIN_URL` is set — presence of that URL is the
    /// on-switch, no separate boolean flag.
    pub hydra_bridge: Option<HydraBridgeConfig>,
}

pub struct HydraBridgeConfig {
    pub admin_url: url::Url,
    pub admin_timeout: Duration,
    pub bridge_origin: String,
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
        let factor_policy = match std::env::var("SURGE_FACTOR_POLICY")
            .unwrap_or_else(|_| "none".to_string())
            .as_str()
        {
            "totp" => FactorPolicy::Totp,
            "passphrase" => FactorPolicy::Passphrase,
            "both" => FactorPolicy::Both,
            _ => FactorPolicy::None,
        };
        let session_cors_origins = std::env::var("SURGE_SESSION_CORS_ORIGINS")
            .ok()
            .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();
        let allow_served_inline = std::env::var("SURGE_ALLOW_SERVED_INLINE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let hydra_bridge = match std::env::var("SURGE_HYDRA_ADMIN_URL").ok() {
            Some(admin_url) => {
                let admin_url = url::Url::parse(&admin_url)
                    .map_err(|e| anyhow::anyhow!("SURGE_HYDRA_ADMIN_URL is not a valid URL: {e}"))?;
                let bridge_origin = std::env::var("SURGE_HYDRA_BRIDGE_ORIGIN").map_err(|_| {
                    anyhow::anyhow!(
                        "SURGE_HYDRA_ADMIN_URL is set but SURGE_HYDRA_BRIDGE_ORIGIN is not; \
                         the bridge needs this server's own public origin to build its \
                         return_to callback"
                    )
                })?;
                let admin_timeout_secs: u64 = std::env::var("SURGE_HYDRA_ADMIN_TIMEOUT_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(10);
                Some(HydraBridgeConfig {
                    admin_url,
                    admin_timeout: Duration::from_secs(admin_timeout_secs),
                    bridge_origin,
                })
            }
            None => None,
        };

        Ok(Self {
            database_url,
            pepper,
            bind_addr,
            cookie_domain,
            auth_ui_origin,
            session_ttl_hours,
            registration,
            factor_policy,
            session_cors_origins,
            allow_served_inline,
            hydra_bridge,
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
