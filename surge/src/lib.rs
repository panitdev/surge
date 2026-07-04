mod extract;
mod remote;
mod traits;

#[cfg(feature = "embedded")]
mod embedded;

pub use extract::AuthSession;
pub use traits::AuthProvider;

#[cfg(feature = "embedded")]
pub use embedded::{EmbeddedConfig, EmbeddedProvider};

pub use remote::{RemoteConfig, RemoteProvider};

pub use surge_engine::types::{
    AuthError, AuthMethod, Identity, IdentityId, IdentityState, Password, ProfilePatch,
    RegisterRequest, Session, SessionId, SessionToken, Username, ValidationError,
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
