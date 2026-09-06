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
    /// Opt-in Hydra login/consent bridge
    /// (`docs/integration/hydra-oauth-bridge.md`). `None` unless
    /// `SURGE_HYDRA_ADMIN_URL` is set — presence of that URL is the
    /// on-switch, no separate boolean flag.
    pub hydra_bridge: Option<HydraBridgeConfig>,
    /// Opt-in native OAuth 2.1 / OIDC authorization server
    /// (internal/oauth-as.md). `None` unless `SURGE_OAUTH_ISSUER` is set —
    /// same shape as the Hydra bridge: the URL is the on-switch.
    pub oauth_as: Option<OauthAsSettings>,
}

/// §8's table, parsed. Every default here is the MCP-correct one, and two of
/// them are security parameters rather than preferences: `access_ttl` is the
/// revocation window for any resource server verifying offline, and
/// `allow_dynamic_registration` opens an unauthenticated endpoint.
pub struct OauthAsSettings {
    pub issuer: String,
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
    pub key_rotation: Duration,
    pub allow_dynamic_registration: bool,
    pub require_resource: bool,
    pub default_resource: Option<String>,
    pub dcr_ttl: Duration,
    pub enable_oidc: bool,
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

        let oauth_as = match std::env::var("SURGE_OAUTH_ISSUER").ok() {
            Some(issuer) => {
                let parsed = url::Url::parse(&issuer)
                    .map_err(|e| anyhow::anyhow!("SURGE_OAUTH_ISSUER is not a valid URL: {e}"))?;
                if parsed.scheme() != "https" && !is_loopback(&bind_addr) {
                    anyhow::bail!(
                        "SURGE_OAUTH_ISSUER ({issuer}) is not https and this server is not bound \
                         to loopback; an issuer reachable over plaintext makes every token it \
                         signs interceptable in transit"
                    );
                }
                Some(OauthAsSettings {
                    issuer: issuer.trim_end_matches('/').to_string(),
                    access_ttl: Duration::from_secs(env_u64("SURGE_OAUTH_ACCESS_TTL_SECS", 600)),
                    refresh_ttl: Duration::from_secs(
                        env_u64("SURGE_OAUTH_REFRESH_TTL_DAYS", 30) * 86_400,
                    ),
                    key_rotation: Duration::from_secs(
                        env_u64("SURGE_OAUTH_KEY_ROTATION_DAYS", 90) * 86_400,
                    ),
                    allow_dynamic_registration: env_flag(
                        "SURGE_OAUTH_ALLOW_DYNAMIC_REGISTRATION",
                        false,
                    ),
                    require_resource: env_flag("SURGE_OAUTH_REQUIRE_RESOURCE", true),
                    default_resource: std::env::var("SURGE_OAUTH_DEFAULT_RESOURCE").ok(),
                    dcr_ttl: Duration::from_secs(env_u64("SURGE_OAUTH_DCR_TTL_DAYS", 30) * 86_400),
                    enable_oidc: env_flag("SURGE_OAUTH_ENABLE_OIDC", true),
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
            oauth_as,
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

impl ServerConfig {
    /// Whether the open-registration warning applies. A method rather than a
    /// field read so the condition lives next to nothing else that could
    /// drift from it.
    pub fn allow_dynamic_registration_warning(&self) -> bool {
        self.oauth_as
            .as_ref()
            .is_some_and(|o| o.allow_dynamic_registration)
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_flag(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        Err(_) => default,
    }
}

/// Whether the bind address is loopback — the one case where a plaintext
/// issuer is legitimate, because nothing leaves the machine.
fn is_loopback(bind_addr: &str) -> bool {
    let host = bind_addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind_addr);
    matches!(host.trim_matches(['[', ']']), "127.0.0.1" | "::1" | "localhost")
}
