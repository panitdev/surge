use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use surge::{AuthProvider, EmbeddedProvider};
use surge_server::{cli, config};

#[derive(Parser)]
#[command(name = "surge-server", about = "Surge authentication server")]
enum Cli {
    Serve(cli::ServeArgs),
    #[command(subcommand)]
    Identity(cli::IdentityCommand),
    #[command(subcommand)]
    Svc(cli::SvcCommand),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config = config::ServerConfig::from_env()?;

    let embedded = EmbeddedProvider::new(config.embedded_config()).await?;
    let engine = embedded.engine();
    let provider: Arc<dyn AuthProvider> = Arc::new(embedded);

    match cli {
        Cli::Serve(args) => cli::serve(args, engine, provider, config).await,
        Cli::Identity(cmd) => cli::identity(cmd, engine).await,
        Cli::Svc(cmd) => cli::svc(cmd, engine).await,
    }
}
