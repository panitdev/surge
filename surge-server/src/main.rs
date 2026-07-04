mod api;
mod cli;
mod config;

use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use surge_engine::Engine;

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
    let engine = Arc::new(Engine::new(config.engine_config()?).await?);
    engine.run_migrations().await?;

    match cli {
        Cli::Serve(args) => cli::serve(args, engine, config).await,
        Cli::Identity(cmd) => cli::identity(cmd, engine).await,
        Cli::Svc(cmd) => cli::svc(cmd, engine).await,
    }
}
