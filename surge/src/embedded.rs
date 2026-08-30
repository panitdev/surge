use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use surge_engine::{Engine, EngineConfig, PepperConfig};

use crate::traits::AuthProvider;
use crate::*;

pub struct EmbeddedConfig {
    pub database_url: SecretString,
    pub pepper: SecretString,
    pub session_ttl: Duration,
}

pub struct EmbeddedProvider {
    engine: Arc<Engine>,
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
        })
        .await?;

        engine.run_migrations().await?;

        Ok(Self {
            engine: Arc::new(engine),
        })
    }

    /// Access to the underlying engine, shared with anything that needs to
    /// sit at the perimeter alongside this provider — a `RateLimiter`
    /// backed by the same pool, or `surge::router::browser`'s flow state
    /// and `spawn_maintenance()`. Not part of `AuthProvider`: flows and the
    /// counter store are router/perimeter concerns, not trusted-primitive
    /// ones.
    pub fn engine(&self) -> Arc<Engine> {
        Arc::clone(&self.engine)
    }
}

#[async_trait]
impl AuthProvider for EmbeddedProvider {
    async fn verify_session(&self, token: Option<SessionToken>) -> Result<Session, AuthError> {
        let token = token.ok_or(AuthError::InvalidToken)?;
        self.engine.verify_session(&token).await
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
        let identity = self
            .engine
            .create_identity(&req.username, &req.display_name)
            .await?;
        self.engine.set_password(identity.id, &req.password).await?;

        self.engine
            .audit(
                surge_engine::audit::AuditActor::Identity {
                    id: identity.id.to_string(),
                },
                "register",
                serde_json::json!({ "identity_id": identity.id.to_string() }),
                None,
            )
            .await?;

        Ok(identity)
    }

    async fn register_and_authenticate(
        &self,
        req: RegisterRequest,
    ) -> Result<IssuedSession, AuthError> {
        let issued = self.engine.create_identity_and_session(req).await?;

        self.engine
            .audit(
                surge_engine::audit::AuditActor::Identity {
                    id: issued.session.identity.id.to_string(),
                },
                "register_and_authenticate",
                serde_json::json!({ "session_id": issued.session.id.to_string() }),
                None,
            )
            .await?;

        Ok(issued)
    }

    async fn authenticate_password(
        &self,
        username: &Username,
        password: &Password,
    ) -> Result<IssuedSession, AuthError> {
        let identity = self.engine.verify_credential(username, password).await?;
        let issued = self
            .engine
            .mint_session(identity.id, AuthMethod::Password)
            .await?;

        self.engine
            .audit(
                surge_engine::audit::AuditActor::Identity {
                    id: identity.id.to_string(),
                },
                "authenticate",
                serde_json::json!({ "session_id": issued.session.id.to_string() }),
                None,
            )
            .await?;

        Ok(issued)
    }

    async fn authenticate_by_link(
        &self,
        provider: &str,
        subject: &str,
        seed: &LinkSeed,
    ) -> Result<LinkAuth, AuthError> {
        let auth = self
            .engine
            .authenticate_by_link(provider, subject, seed)
            .await?;

        self.engine
            .audit(
                surge_engine::audit::AuditActor::Identity {
                    id: auth.issued.session.identity.id.to_string(),
                },
                if auth.created {
                    "register_by_link"
                } else {
                    "authenticate_by_link"
                },
                serde_json::json!({
                    "session_id": auth.issued.session.id.to_string(),
                    "provider": provider,
                }),
                None,
            )
            .await?;

        Ok(auth)
    }

    async fn link_identity(
        &self,
        identity_id: IdentityId,
        provider: &str,
        subject: &str,
        verified: bool,
    ) -> Result<IdentityLink, AuthError> {
        let link = self
            .engine
            .link_identity(identity_id, provider, subject, verified)
            .await?;

        self.engine
            .audit(
                surge_engine::audit::AuditActor::Identity {
                    id: identity_id.to_string(),
                },
                "link_identity",
                serde_json::json!({
                    "provider": provider,
                    "subject": subject,
                    "verified": link.is_verified(),
                }),
                None,
            )
            .await?;

        Ok(link)
    }

    async fn identity_links(&self, identity_id: IdentityId) -> Result<Vec<IdentityLink>, AuthError> {
        self.engine.identity_links(identity_id).await
    }

    async fn unlink_identity(
        &self,
        identity_id: IdentityId,
        provider: &str,
        subject: &str,
    ) -> Result<(), AuthError> {
        self.engine
            .unlink_identity(identity_id, provider, subject)
            .await?;

        self.engine
            .audit(
                surge_engine::audit::AuditActor::Identity {
                    id: identity_id.to_string(),
                },
                "unlink_identity",
                serde_json::json!({
                    "provider": provider,
                    "subject": subject,
                }),
                None,
            )
            .await?;

        Ok(())
    }

    async fn run_maintenance(&self) -> Result<(), AuthError> {
        self.engine.gc_expired_sessions().await?;
        self.engine.gc_expired_login_flows().await?;
        Ok(())
    }

    #[cfg(feature = "router")]
    fn browser_router(
        self: Arc<Self>,
        config: crate::router::BrowserRouterConfig,
    ) -> axum::Router {
        let engine = self.engine();
        crate::router::embedded_browser_router(
            engine,
            self as Arc<dyn AuthProvider>,
            config,
        )
    }
}
