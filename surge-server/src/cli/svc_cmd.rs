use std::sync::Arc;

use clap::Subcommand;
use surge_engine::types::ServiceToken;
use surge_engine::Engine;

#[derive(Subcommand)]
pub enum SvcCommand {
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, num_args = 1..)]
        grant: Vec<String>,
        #[arg(long, num_args = 0..)]
        origin: Vec<String>,
    },
    List,
    Revoke {
        #[arg(help = "Service name")]
        name: String,
    },
}

pub async fn svc(cmd: SvcCommand, engine: Arc<Engine>) -> anyhow::Result<()> {
    match cmd {
        SvcCommand::Create {
            name,
            grant,
            origin,
        } => {
            let valid_grants = [
                "introspect",
                "identity_read",
                "identity_write",
                "direct_auth",
                "revoke",
            ];
            for g in &grant {
                if !valid_grants.contains(&g.as_str()) {
                    anyhow::bail!("unknown grant: {g}. Valid: {}", valid_grants.join(", "));
                }
            }

            let token = ServiceToken::generate();
            let svc = engine
                .create_service(&name, token.hash(), grant, origin)
                .await?;

            println!("Service created:");
            println!("  ID:     {}", svc.id);
            println!("  Name:   {}", svc.name);
            println!("  Grants: {:?}", svc.grants);
            println!("  Token:  {}", token.expose_secret());
            println!();
            println!("Store this token securely — it cannot be retrieved again.");

            engine
                .audit(
                    surge_engine::audit::AuditActor::Operator {
                        name: std::env::var("USER").unwrap_or_else(|_| "unknown".into()),
                    },
                    "create_service",
                    serde_json::json!({"service_id": svc.id.to_string(), "name": svc.name}),
                    None,
                )
                .await?;
        }
        SvcCommand::List => {
            let services = engine.list_services().await?;
            if services.is_empty() {
                println!("No registered services.");
            } else {
                for svc in services {
                    println!(
                        "{} ({}): grants={:?} origins={:?}",
                        svc.name, svc.id, svc.grants, svc.return_origins
                    );
                }
            }
        }
        SvcCommand::Revoke { name } => {
            engine.revoke_service(&name).await?;
            println!("Service {} revoked.", name);

            engine
                .audit(
                    surge_engine::audit::AuditActor::Operator {
                        name: std::env::var("USER").unwrap_or_else(|_| "unknown".into()),
                    },
                    "revoke_service",
                    serde_json::json!({"name": name}),
                    None,
                )
                .await?;
        }
    }

    Ok(())
}
