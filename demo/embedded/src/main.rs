use std::time::Duration;

use secrecy::SecretString;
use surge::EmbeddedConfig;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let bind = std::env::var("DEMO_BIND").unwrap_or_else(|_| "127.0.0.1:3100".into());
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/surge_demo_embedded".into());
    let pepper =
        std::env::var("SURGE_PEPPER").unwrap_or_else(|_| "local-demo-pepper-change-me".into());

    info!(%database_url, %bind, "embedded demo starting");
    let auth = surge::embedded(EmbeddedConfig {
        database_url: SecretString::from(database_url),
        pepper: SecretString::from(pepper),
        session_ttl: Duration::from_secs(72 * 60 * 60),
    })
    .await?;

    let listener = TcpListener::bind(&bind).await?;
    info!("embedded demo listening at http://{bind}");
    axum::serve(listener, surge_demo_common::app(auth)).await?;
    Ok(())
}
