use std::time::Duration;

use secrecy::SecretString;
use surge::EmbeddedConfig;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bind = std::env::var("DEMO_BIND").unwrap_or_else(|_| "127.0.0.1:3100".into());
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/surge_demo_embedded".into());
    let pepper =
        std::env::var("SURGE_PEPPER").unwrap_or_else(|_| "local-demo-pepper-change-me".into());

    let auth = surge::embedded(EmbeddedConfig {
        database_url: SecretString::from(database_url),
        pepper: SecretString::from(pepper),
        session_ttl: Duration::from_secs(72 * 60 * 60),
        gc_interval: Some(Duration::from_secs(15 * 60)),
    })
    .await?;

    let listener = TcpListener::bind(&bind).await?;
    println!("embedded demo listening at http://{bind}");
    axum::serve(listener, surge_demo_common::app(auth)).await?;
    Ok(())
}
