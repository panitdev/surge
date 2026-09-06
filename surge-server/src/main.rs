use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use surge::EmbeddedProvider;
use surge_server::{cli, config};

#[derive(Parser)]
#[command(name = "surge-server", about = "Surge authentication server")]
enum Cli {
    Serve(cli::ServeArgs),
    #[command(subcommand)]
    Identity(cli::IdentityCommand),
    #[command(subcommand)]
    Svc(cli::SvcCommand),
    #[command(subcommand)]
    Oauth(cli::OauthCommand),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config = config::ServerConfig::from_env()?;

    let embedded = Arc::new(EmbeddedProvider::new(config.embedded_config()).await?);
    let engine = embedded.engine();

    match cli {
        Cli::Serve(args) => cli::serve(args, Arc::clone(&embedded), config).await,
        Cli::Identity(cmd) => cli::identity(cmd, engine).await,
        Cli::Svc(cmd) => cli::svc(cmd, engine).await,
        Cli::Oauth(cmd) => cli::oauth(cmd, engine).await,
    }
}
