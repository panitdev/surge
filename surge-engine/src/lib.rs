pub mod credential;
pub mod schema;
pub mod types;

pub mod audit;
pub mod oauth;
mod browser_mutation;
mod browser_session;
pub use browser_session::{BrowserAccountList, IssuedBrowserSession};

mod counter;
mod crypto;
mod factor;
mod flow;
mod login_completion;
pub use login_completion::{CompletedLogin, PassphraseProof, PasswordProof, VerifiedLogin};
mod identity;
mod link;
mod models;
mod service;
mod session;

pub use factor::{FactorStatus, TotpEnrollment};

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
    /// The global dynamic-client-registration switch, as the authorization
    /// server mounted on this engine was configured. See
    /// [`oauth::EligibilityPolicy`]. Off until the AS says otherwise.
    dynamic_clients_enabled: std::sync::atomic::AtomicBool,
}

impl Engine {
    /// Sets the global DCR switch the eligibility rule consults. It is a
    /// kill switch: while off, dynamically registered clients are ineligible
    /// everywhere, whatever any resource's own opt-in says.
    pub fn set_dynamic_clients_enabled(&self, enabled: bool) {
        self.dynamic_clients_enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// The policy inputs that are deployment-wide rather than per resource.
    pub fn eligibility_policy(&self) -> oauth::EligibilityPolicy {
        oauth::EligibilityPolicy {
            dynamic_clients_enabled: self
                .dynamic_clients_enabled
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    pub async fn new(config: EngineConfig) -> Result<Self, anyhow::Error> {
        let db_url = config.database_url.expose_secret().to_string();
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&db_url);
        let pool = Pool::builder(manager).build()?;

        Ok(Self {
            pool,
            database_url: db_url,
            pepper: config.pepper,
            session_ttl: config.session_ttl,
            dynamic_clients_enabled: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub async fn run_migrations(&self) -> Result<(), anyhow::Error> {
        use diesel::{Connection, RunQueryDsl};
        use diesel_migrations::MigrationHarness;

        let url = self.database_url.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = diesel::PgConnection::establish(&url)?;
            // Hold the lock on this dedicated connection across all migration transactions.
            diesel::sql_query("SELECT pg_advisory_lock(1937076839, 1)").execute(&mut conn)?;
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
