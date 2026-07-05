use std::time::Duration;

use secrecy::SecretString;
use surge::RemoteConfig;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;
use url::Url;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let bind = std::env::var("DEMO_BIND").unwrap_or_else(|_| "127.0.0.1:3200".into());
    let base_url = std::env::var("SURGE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".into());
    let service_token = std::env::var("SURGE_SERVICE_TOKEN")
        .map_err(|_| anyhow::anyhow!("SURGE_SERVICE_TOKEN is required"))?;

    let auth = surge::remote(RemoteConfig {
        base_url: Url::parse(&base_url)?,
        service_token: SecretString::from(service_token),
        cache_ttl: Duration::from_secs(30),
        cache_max_entries: 10_000,
        timeout: Duration::from_secs(3),
    })
    .await?;

    info!(%base_url, %bind, "served demo starting");
    let listener = TcpListener::bind(&bind).await?;
    info!("served demo listening at http://{bind}");
    axum::serve(listener, surge_demo_common::app(auth)).await?;
    Ok(())
}
