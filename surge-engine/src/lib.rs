pub mod credential;
pub mod schema;
pub mod types;

pub mod audit;
mod counter;
mod flow;
mod identity;
mod models;
mod service;
mod session;

use std::time::Duration;

use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::AsyncPgConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations};
use secrecy::{ExposeSecret, SecretString};

pub use counter::WindowCount;
pub use types::*;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub struct EngineConfig {
    pub database_url: SecretString,
    pub pepper: PepperConfig,
    pub session_ttl: Duration,
}

pub struct PepperConfig {
    pub current_version: u8,
    pub peppers: std::collections::HashMap<u8, SecretString>,
}

pub struct Engine {
    pool: Pool<AsyncPgConnection>,
    database_url: String,
    pepper: PepperConfig,
    session_ttl: Duration,
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
