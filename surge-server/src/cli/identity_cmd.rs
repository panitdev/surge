use std::sync::Arc;

use clap::Subcommand;
use surge_engine::types::*;
use surge_engine::Engine;

#[derive(Subcommand)]
pub enum IdentityCommand {
    ResetPassword {
        #[arg(help = "Username of the identity")]
        username: String,
    },
    Disable {
        #[arg(help = "Username of the identity")]
        username: String,
    },
    Enable {
        #[arg(help = "Username of the identity")]
        username: String,
    },
    Rename {
        #[arg(help = "Current username")]
        username: String,
        #[arg(help = "New username")]
        new_username: String,
    },
}

pub async fn identity(cmd: IdentityCommand, engine: Arc<Engine>) -> anyhow::Result<()> {
    match cmd {
        IdentityCommand::ResetPassword { username } => {
            let username = Username::new(&username)?;
            let ident = engine.get_identity_by_username(&username).await?;

            let temp_raw: String = {
                use rand::Rng;
                let mut rng = rand::rng();
                (0..24)
                    .map(|_| {
                        let idx = rng.random_range(0..62u32);
                        match idx {
                            0..=9 => (b'0' + idx as u8) as char,
                            10..=35 => (b'a' + (idx - 10) as u8) as char,
                            _ => (b'A' + (idx - 36) as u8) as char,
                        }
                    })
                    .collect()
            };
            let temp_password = Password::new(secrecy::SecretString::from(temp_raw.clone()))?;
            engine.set_password(ident.id, &temp_password).await?;
            engine.revoke_all_sessions(ident.id).await?;

            println!("Temporary password for {}: {}", username, temp_raw);
            println!("All existing sessions revoked.");
            println!("Deliver this password to the user out-of-band.");
            println!("The user should change it after login.");

            engine
                .audit(
                    surge_engine::audit::AuditActor::Operator {
                        name: std::env::var("USER").unwrap_or_else(|_| "unknown".into()),
                    },
                    "reset_password",
                    serde_json::json!({"identity_id": ident.id.to_string(), "username": username.as_str()}),
                    None,
                )
                .await?;
        }
        IdentityCommand::Disable { username } => {
            let username = Username::new(&username)?;
            let ident = engine.get_identity_by_username(&username).await?;
            engine
                .set_identity_state(ident.id, IdentityState::Disabled)
                .await?;
            engine.revoke_all_sessions(ident.id).await?;

            engine
                .audit(
                    surge_engine::audit::AuditActor::Operator {
                        name: std::env::var("USER").unwrap_or_else(|_| "unknown".into()),
                    },
                    "disable_identity",
                    serde_json::json!({"identity_id": ident.id.to_string(), "username": username.as_str()}),
                    None,
                )
                .await?;

            println!("Identity {} disabled, all sessions revoked.", username);
        }
        IdentityCommand::Enable { username } => {
            let username = Username::new(&username)?;
            let ident = engine.get_identity_by_username(&username).await?;
            engine
                .set_identity_state(ident.id, IdentityState::Active)
                .await?;

            engine
                .audit(
                    surge_engine::audit::AuditActor::Operator {
                        name: std::env::var("USER").unwrap_or_else(|_| "unknown".into()),
                    },
                    "enable_identity",
                    serde_json::json!({"identity_id": ident.id.to_string(), "username": username.as_str()}),
                    None,
                )
                .await?;

            println!("Identity {} enabled.", username);
        }
        IdentityCommand::Rename {
            username,
            new_username,
        } => {
            let username = Username::new(&username)?;
            let new_username = Username::new(&new_username)?;
            let ident = engine.get_identity_by_username(&username).await?;

            println!("WARNING: Renaming {} -> {}", username, new_username);
            println!();
            println!("Downstream systems to update manually:");
            println!("  - Herald: update mailbox address {}@panit.dev -> {}@panit.dev", username, new_username);
            println!("  - Any service storing username as display string");
            println!();
            println!("This operation is NOT atomic across services.");
            println!("Identity ID {} remains stable.", ident.id);

            engine
                .audit(
                    surge_engine::audit::AuditActor::Operator {
                        name: std::env::var("USER").unwrap_or_else(|_| "unknown".into()),
                    },
                    "rename_identity",
                    serde_json::json!({
                        "identity_id": ident.id.to_string(),
                        "old_username": username.as_str(),
                        "new_username": new_username.as_str(),
                    }),
                    None,
                )
                .await?;
        }
    }

    Ok(())
}
