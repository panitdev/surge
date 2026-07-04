use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use surge_engine::{Engine, EngineConfig, PepperConfig, RateLimitConfig};
use tokio::task::JoinHandle;
use tracing::info;

use crate::traits::AuthProvider;
use crate::*;

pub struct EmbeddedConfig {
    pub database_url: SecretString,
    pub pepper: SecretString,
    pub session_ttl: Duration,
    pub gc_interval: Option<Duration>,
}

pub struct EmbeddedProvider {
    engine: Arc<Engine>,
    _gc_handle: Option<JoinHandle<()>>,
}

impl EmbeddedProvider {
    pub async fn new(config: EmbeddedConfig) -> Result<Self, anyhow::Error> {
        let mut peppers = HashMap::new();
        peppers.insert(1u8, config.pepper);

        let engine = Engine::new(EngineConfig {
            database_url: config.database_url,
            pepper: PepperConfig {
                current_version: 1,
                peppers,
            },
            session_ttl: config.session_ttl,
            rate_limit: RateLimitConfig::default(),
        })
        .await?;

        engine.run_migrations().await?;

        let engine = Arc::new(engine);
        let gc_handle = config.gc_interval.map(|interval| {
            let engine = Arc::clone(&engine);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(interval).await;
                    match engine.gc_expired_sessions().await {
                        Ok(n) if n > 0 => info!(deleted = n, "session gc"),
                        Err(e) => tracing::warn!(error = %e, "session gc failed"),
                        _ => {}
                    }
                }
            })
        });

        Ok(Self {
            engine,
            _gc_handle: gc_handle,
        })
    }
}

#[async_trait]
impl AuthProvider for EmbeddedProvider {
    async fn verify_session(&self, token: &SessionToken) -> Result<Session, AuthError> {
        self.engine.verify_session(token).await
    }

    async fn revoke_session(&self, token: &SessionToken) -> Result<(), AuthError> {
        self.engine.revoke_session(token).await
    }

    async fn revoke_all_sessions(&self, id: IdentityId) -> Result<u64, AuthError> {
        self.engine.revoke_all_sessions(id).await
    }

    async fn identity(&self, id: IdentityId) -> Result<Identity, AuthError> {
        self.engine.get_identity(id).await
    }

    async fn identity_by_username(&self, username: &Username) -> Result<Identity, AuthError> {
        self.engine.get_identity_by_username(username).await
    }

    async fn update_profile(
        &self,
        id: IdentityId,
        patch: ProfilePatch,
    ) -> Result<Identity, AuthError> {
        self.engine.update_profile(id, &patch).await
    }

    async fn register(&self, req: RegisterRequest) -> Result<Identity, AuthError> {
        self.engine.register(req, None).await
    }

    async fn authenticate_password(
        &self,
        username: &Username,
        password: &Password,
    ) -> Result<Session, AuthError> {
        let (session, _token) = self.engine.authenticate_password(username, password, None).await?;
        Ok(session)
    }
}
