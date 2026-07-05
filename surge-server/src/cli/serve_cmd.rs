use std::net::SocketAddr;
use std::sync::Arc;

use clap::Args;
use tokio::net::TcpListener;
use tracing::info;

use surge::AuthProvider;
use surge_engine::Engine;

use crate::api;
use crate::config::ServerConfig;

#[derive(Args)]
pub struct ServeArgs {
    #[arg(long, env = "SURGE_BIND")]
    bind: Option<String>,
}

pub async fn serve(
    args: ServeArgs,
    engine: Arc<Engine>,
    provider: Arc<dyn AuthProvider>,
    config: ServerConfig,
) -> anyhow::Result<()> {
    let bind = args.bind.unwrap_or_else(|| config.bind_addr.clone());
    let config = Arc::new(config);
    let app = api::router(engine, provider, config).await?;

    let listener = TcpListener::bind(&bind).await?;
    info!(addr = %bind, "surge-server listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
