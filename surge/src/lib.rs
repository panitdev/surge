mod extract;
pub mod hydra;
mod remote;
mod traits;

#[cfg(feature = "embedded")]
mod embedded;

#[cfg(feature = "test-provider")]
mod test_provider;

#[cfg(feature = "router")]
pub mod router;

pub use extract::{require_header_csrf, me_logout_router, AuthSession};
pub use traits::AuthProvider;

#[cfg(feature = "embedded")]
pub use embedded::{EmbeddedConfig, EmbeddedProvider};

#[cfg(feature = "test-provider")]
pub use test_provider::{TestConfig, TestProvider};

pub use remote::{RemoteConfig, RemoteProvider};

pub use surge_engine::types::{
    AuthError, AuthMethod, Identity, IdentityId, IdentityState, IssuedSession, Password,
    ProfilePatch, RegisterRequest, Session, SessionId, SessionToken, Username, ValidationError,
};

#[cfg(feature = "embedded")]
pub async fn embedded(
    config: EmbeddedConfig,
) -> Result<std::sync::Arc<dyn AuthProvider>, anyhow::Error> {
    let provider = EmbeddedProvider::new(config).await?;
    Ok(std::sync::Arc::new(provider))
}

pub async fn remote(
    config: RemoteConfig,
) -> Result<std::sync::Arc<dyn AuthProvider>, anyhow::Error> {
    let provider = RemoteProvider::new(config)?;
    Ok(std::sync::Arc::new(provider))
}

#[cfg(feature = "test-provider")]
pub fn test(config: TestConfig) -> Result<std::sync::Arc<dyn AuthProvider>, anyhow::Error> {
    let provider = TestProvider::new(config)?;
    Ok(std::sync::Arc::new(provider))
}
