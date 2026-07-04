pub mod credential;
pub mod schema;
pub mod types;

pub mod audit;
mod flow;
mod identity;
mod models;
pub mod rate_limit;
mod service;
mod session;

use std::time::Duration;

use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::AsyncPgConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations};
use secrecy::{ExposeSecret, SecretString};

pub use types::*;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub struct EngineConfig {
    pub database_url: SecretString,
    pub pepper: PepperConfig,
    pub session_ttl: Duration,
    pub rate_limit: RateLimitConfig,
}

pub struct PepperConfig {
    pub current_version: u8,
    pub peppers: std::collections::HashMap<u8, SecretString>,
}

pub struct RateLimitConfig {
    pub auth_window: Duration,
    pub auth_max_attempts: u32,
    pub register_window: Duration,
    pub register_max_attempts: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            auth_window: Duration::from_secs(900),
            auth_max_attempts: 10,
            register_window: Duration::from_secs(3600),
            register_max_attempts: 5,
        }
    }
}

pub struct Engine {
    pool: Pool<AsyncPgConnection>,
    database_url: String,
    pepper: PepperConfig,
    session_ttl: Duration,
    rate_limit: RateLimitConfig,
    rate_limiter: rate_limit::RateLimiter,
}

impl Engine {
    pub async fn new(config: EngineConfig) -> Result<Self, anyhow::Error> {
        let db_url = config.database_url.expose_secret().to_string();
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&db_url);
        let pool = Pool::builder(manager).build()?;

        Ok(Self {
            pool,
            database_url: db_url,
            pepper: config.pepper,
            session_ttl: config.session_ttl,
            rate_limit: config.rate_limit,
            rate_limiter: rate_limit::RateLimiter::new(),
        })
    }

    pub async fn run_migrations(&self) -> Result<(), anyhow::Error> {
        use diesel::Connection;
        use diesel_migrations::MigrationHarness;

        let url = self.database_url.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = diesel::PgConnection::establish(&url)?;
            conn.run_pending_migrations(MIGRATIONS)
                .map_err(|e| anyhow::anyhow!("migration error: {e}"))?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    }

    pub async fn register(
        &self,
        req: RegisterRequest,
        ip: Option<std::net::IpAddr>,
    ) -> Result<Identity, AuthError> {
        self.rate_limiter.check_register(ip, &self.rate_limit)?;

        let identity = self.create_identity(&req.username, &req.display_name).await?;
        self.set_password(identity.id, &req.password).await?;

        self.audit(
            audit::AuditActor::Identity { id: identity.id.to_string() },
            "register",
            serde_json::json!({ "identity_id": identity.id.to_string() }),
            None,
        ).await?;

        Ok(identity)
    }

    pub async fn authenticate_password(
        &self,
        username: &Username,
        password: &Password,
        ip: Option<std::net::IpAddr>,
    ) -> Result<(Session, SessionToken), AuthError> {
        self.rate_limiter.check_auth(ip, username.as_str(), &self.rate_limit)?;

        let identity = self.verify_password(username, password).await?;
        let token = SessionToken::generate();
        let session = self.create_session(identity.id, &token, AuthMethod::Password).await?;

        self.audit(
            audit::AuditActor::Identity { id: identity.id.to_string() },
            "authenticate",
            serde_json::json!({ "session_id": session.id.to_string() }),
            None,
        ).await?;

        Ok((session, token))
    }

    pub(crate) async fn conn(
        &self,
    ) -> Result<deadpool::managed::Object<AsyncDieselConnectionManager<AsyncPgConnection>>, AuthError>
    {
        self.pool
            .get()
            .await
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("pool error: {e}")))
    }
}
