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
    pub browser_public_origin: Option<String>,
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
    pub multi_account: bool,
    /// Opt-in native OAuth 2.1 / OIDC authorization server
    /// (internal/oauth-as.md). Enabled by setting `SURGE_OAUTH_ISSUER`.
    pub oauth_as: Option<OauthAsSettings>,
}

const DEFAULT_ACCESS_TTL_SECS: u64 = 600;

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
    /// Replaces the HTTPS document fetcher for client-ID metadata documents.
    /// Not configurable from the environment: production always uses the
    /// SSRF-hardened fetcher, and this exists so tests can serve documents
    /// without the network.
    pub cimd_fetcher: Option<std::sync::Arc<dyn surge::router::CimdDocumentFetcher>>,
}

impl ServerConfig {
    /// The access-token lifetime this process is configured with, if the
    /// authorization server is enabled. Deleting a resource reserves its URI
    /// for the longer of this and the persisted high-water mark of every
    /// lifetime ever configured.
    pub fn oauth_access_ttl(&self) -> Option<Duration> {
        self.oauth_as.as_ref().map(|o| o.access_ttl)
    }

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

        let oauth_as = match std::env::var("SURGE_OAUTH_ISSUER").ok() {
            Some(issuer) => {
                let issuer = validate_issuer(&issuer, &bind_addr)?;
                Some(OauthAsSettings {
                    issuer,
                    access_ttl: Duration::from_secs(env_u64("SURGE_OAUTH_ACCESS_TTL_SECS", DEFAULT_ACCESS_TTL_SECS)),
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
                    cimd_fetcher: None,
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
            browser_public_origin: std::env::var("SURGE_BROWSER_PUBLIC_ORIGIN").ok(),
            session_ttl_hours,
            registration,
            factor_policy,
            session_cors_origins,
            allow_served_inline,
            multi_account: std::env::var("SURGE_MULTI_ACCOUNT").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
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

/// Validate `SURGE_OAUTH_ISSUER` and return its canonical (slash-less) form.
///
/// The issuer must be a bare origin. RFC 8414 §3.1 puts a path-ful issuer's
/// metadata at `/.well-known/oauth-authorization-server/<path>` and its
/// endpoints under `<path>`, but Surge mounts both at the origin root, and
/// return-origin matching compares origins only. A path-ful issuer would
/// therefore advertise endpoints that do not exist, so it is refused here
/// rather than half-supported. RFC 8414 §2 forbids a query or fragment.
fn validate_issuer(issuer: &str, bind_addr: &str) -> anyhow::Result<String> {
    let parsed = url::Url::parse(issuer)
        .map_err(|e| anyhow::anyhow!("SURGE_OAUTH_ISSUER is not a valid URL: {e}"))?;
    if parsed.scheme() != "https" && !is_loopback(bind_addr) {
        anyhow::bail!(
            "SURGE_OAUTH_ISSUER ({issuer}) is not https and this server is not bound \
             to loopback; an issuer reachable over plaintext makes every token it \
             signs interceptable in transit"
        );
    }
    if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
        anyhow::bail!(
            "SURGE_OAUTH_ISSUER ({issuer}) must be a bare origin such as \
             https://auth.example.com, with no path, query or fragment; the OAuth \
             endpoints and metadata are served at the origin root"
        );
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("SURGE_OAUTH_ISSUER ({issuer}) must not contain credentials");
    }
    Ok(issuer.trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::validate_issuer;

    const PUBLIC: &str = "0.0.0.0:8080";

    #[test]
    fn bare_origin_issuers_are_accepted_and_canonicalized() {
        assert_eq!(validate_issuer("https://auth.example.com", PUBLIC).unwrap(), "https://auth.example.com");
        assert_eq!(validate_issuer("https://auth.example.com/", PUBLIC).unwrap(), "https://auth.example.com");
        assert_eq!(validate_issuer("https://auth.example.com:8443", PUBLIC).unwrap(), "https://auth.example.com:8443");
    }

    #[test]
    fn path_ful_issuers_are_rejected() {
        for issuer in ["https://host/idp", "https://host/idp/", "https://host//"] {
            let err = validate_issuer(issuer, PUBLIC).unwrap_err().to_string();
            assert!(err.contains("bare origin"), "{issuer}: {err}");
        }
    }

    #[test]
    fn query_fragment_and_credentials_are_rejected() {
        for issuer in ["https://host?x=1", "https://host/#frag", "https://user:pw@host"] {
            assert!(validate_issuer(issuer, PUBLIC).is_err(), "{issuer} accepted");
        }
    }

    #[test]
    fn plaintext_issuer_needs_a_loopback_bind() {
        assert!(validate_issuer("http://127.0.0.1:8080", PUBLIC).is_err());
        assert_eq!(validate_issuer("http://127.0.0.1:8080", "127.0.0.1:8080").unwrap(), "http://127.0.0.1:8080");
    }
}
