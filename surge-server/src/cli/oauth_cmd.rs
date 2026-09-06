//! `surge-server oauth …` — operator management of OAuth clients, audiences
//! and signing keys.
//!
//! Registering a first-party client and its resource is the setup step before
//! anything can authorize, and it is deliberately a CLI action rather than an
//! API one: `first_party` skips the consent screen, which is exactly the
//! privilege that must never be reachable from an unauthenticated endpoint.

use std::sync::Arc;

use clap::Subcommand;
use surge_engine::oauth::{NewOauthClient, RegistrationSource};
use surge_engine::Engine;

#[derive(Subcommand)]
pub enum OauthCommand {
    /// Manage OAuth clients.
    #[command(subcommand)]
    Client(ClientCommand),
    /// Manage audiences — the resource servers tokens can be scoped to.
    #[command(subcommand)]
    Resource(ResourceCommand),
    /// Manage token-signing keys.
    #[command(subcommand)]
    Key(KeyCommand),
}

#[derive(Subcommand)]
pub enum ClientCommand {
    Create {
        #[arg(long)]
        name: String,
        /// Exact redirect URI. Repeatable. `https`, or `http` on loopback.
        #[arg(long, num_args = 1.., required = true)]
        redirect_uri: Vec<String>,
        /// Scopes this client may ever be granted. Narrowed further per
        /// resource at authorize time.
        #[arg(long, num_args = 0..)]
        scope: Vec<String>,
        /// Issue a client secret (confidential client). Omit for the public,
        /// PKCE-only client that native and MCP clients need.
        #[arg(long)]
        confidential: bool,
        /// Skip the consent screen. Only for clients you operate: it means
        /// this client can obtain a user's tokens with no approval step.
        #[arg(long)]
        first_party: bool,
        #[arg(long)]
        client_uri: Option<String>,
        #[arg(long)]
        logo_uri: Option<String>,
    },
    List,
    Revoke {
        #[arg(help = "Client id (aeg_cid_…)")]
        client_id: String,
    },
}

#[derive(Subcommand)]
pub enum ResourceCommand {
    Create {
        /// Canonical audience URI, e.g. https://dispatch.panit.dev/mcp
        #[arg(long)]
        uri: String,
        /// Name of the registered service that owns this resource server.
        #[arg(long)]
        service: String,
        #[arg(long, num_args = 1.., required = true)]
        scope: Vec<String>,
        /// `scope=human sentence`, repeatable — rendered on the consent
        /// screen. A scope with no description shows its bare name, which is
        /// rarely what you want a person to have to interpret.
        #[arg(long = "describe", num_args = 0..)]
        describe: Vec<String>,
    },
    List,
    Delete {
        uri: String,
    },
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Show the published keys (active plus retiring).
    List,
    /// Generate and activate a new key, retiring the current one.
    Rotate,
}

pub async fn oauth(cmd: OauthCommand, engine: Arc<Engine>) -> anyhow::Result<()> {
    match cmd {
        OauthCommand::Client(cmd) => client(cmd, engine).await,
        OauthCommand::Resource(cmd) => resource(cmd, engine).await,
        OauthCommand::Key(cmd) => key(cmd, engine).await,
    }
}

async fn client(cmd: ClientCommand, engine: Arc<Engine>) -> anyhow::Result<()> {
    match cmd {
        ClientCommand::Create {
            name,
            redirect_uri,
            scope,
            confidential,
            first_party,
            client_uri,
            logo_uri,
        } => {
            let (client, secret) = engine
                .create_oauth_client(NewOauthClient {
                    client_name: name,
                    client_uri,
                    logo_uri,
                    redirect_uris: redirect_uri,
                    grant_types: vec![
                        "authorization_code".to_string(),
                        "refresh_token".to_string(),
                    ],
                    scopes: scope,
                    confidential,
                    first_party,
                    registration_source: RegistrationSource::Admin,
                })
                .await?;

            println!("OAuth client created:");
            println!("  Client ID:   {}", client.client_id);
            println!("  Name:        {}", client.client_name);
            println!("  Redirects:   {:?}", client.redirect_uris);
            println!("  Scopes:      {:?}", client.scopes);
            println!("  First party: {}", client.first_party);
            if let Some(secret) = secret {
                println!("  Secret:      {}", secret.expose_secret());
                println!();
                println!("Store this secret securely — it cannot be retrieved again.");
            } else {
                println!("  Auth:        none (public client, PKCE only)");
            }

            engine
                .audit(
                    operator(),
                    "create_oauth_client",
                    serde_json::json!({
                        "client_id": client.client_id,
                        "first_party": client.first_party,
                    }),
                    None,
                )
                .await?;
        }
        ClientCommand::List => {
            let clients = engine.list_oauth_clients().await?;
            if clients.is_empty() {
                println!("No registered OAuth clients.");
            }
            for client in clients {
                println!(
                    "{} ({}): source={} first_party={} scopes={:?} redirects={:?}",
                    client.client_name,
                    client.client_id,
                    client.registration_source.as_str(),
                    client.first_party,
                    client.scopes,
                    client.redirect_uris,
                );
            }
        }
        ClientCommand::Revoke { client_id } => {
            engine.revoke_oauth_client(&client_id).await?;
            println!("Client {client_id} revoked; its refresh tokens were revoked with it.");

            engine
                .audit(
                    operator(),
                    "revoke_oauth_client",
                    serde_json::json!({ "client_id": client_id }),
                    None,
                )
                .await?;
        }
    }
    Ok(())
}

async fn resource(cmd: ResourceCommand, engine: Arc<Engine>) -> anyhow::Result<()> {
    match cmd {
        ResourceCommand::Create {
            uri,
            service,
            scope,
            describe,
        } => {
            let services = engine.list_services().await?;
            let owner = services
                .into_iter()
                .find(|s| s.name == service)
                .ok_or_else(|| anyhow::anyhow!("no live service named `{service}`"))?;

            let mut descriptions = serde_json::Map::new();
            for entry in describe {
                let (scope, description) = entry.split_once('=').ok_or_else(|| {
                    anyhow::anyhow!("--describe expects `scope=description`, got `{entry}`")
                })?;
                descriptions.insert(
                    scope.to_string(),
                    serde_json::Value::String(description.to_string()),
                );
            }

            let resource = engine
                .create_oauth_resource(
                    &uri,
                    owner.id,
                    scope,
                    serde_json::Value::Object(descriptions),
                )
                .await?;

            println!("OAuth resource created:");
            println!("  Audience: {}", resource.resource_uri);
            println!("  Service:  {} ({})", owner.name, owner.id);
            println!("  Scopes:   {:?}", resource.scopes);

            engine
                .audit(
                    operator(),
                    "create_oauth_resource",
                    serde_json::json!({
                        "resource_uri": resource.resource_uri,
                        "service_id": owner.id.to_string(),
                    }),
                    None,
                )
                .await?;
        }
        ResourceCommand::List => {
            let resources = engine.list_oauth_resources().await?;
            if resources.is_empty() {
                println!("No registered OAuth resources. Every authorize request will fail.");
            }
            for resource in resources {
                println!(
                    "{}: service={} scopes={:?}",
                    resource.resource_uri, resource.service_id, resource.scopes
                );
            }
        }
        ResourceCommand::Delete { uri } => {
            engine.delete_oauth_resource(&uri).await?;
            println!("Resource {uri} deleted.");

            engine
                .audit(
                    operator(),
                    "delete_oauth_resource",
                    serde_json::json!({ "resource_uri": uri }),
                    None,
                )
                .await?;
        }
    }
    Ok(())
}

async fn key(cmd: KeyCommand, engine: Arc<Engine>) -> anyhow::Result<()> {
    match cmd {
        KeyCommand::List => {
            let keys = engine.public_oauth_signing_keys().await?;
            if keys.is_empty() {
                println!("No signing keys yet; one is generated on the first token issued.");
            }
            for key in keys {
                let status = if key.retired_at.is_some() {
                    "retiring"
                } else {
                    "active"
                };
                println!("{} ({}): {}", key.kid, key.algorithm, status);
            }
        }
        KeyCommand::Rotate => {
            // Zero rotation interval: rotate now, whatever the key's age.
            // The retirement grace stays generous so tokens signed a moment
            // ago keep verifying.
            let rotated = engine
                .rotate_oauth_signing_keys(
                    std::time::Duration::ZERO,
                    std::time::Duration::from_secs(3600),
                )
                .await?;
            if rotated {
                println!("Rotated. The previous key stays published until it is retired.");
            } else {
                println!("Nothing to rotate: no key is active yet.");
            }

            engine
                .audit(operator(), "rotate_oauth_signing_key", serde_json::json!({}), None)
                .await?;
        }
    }
    Ok(())
}

fn operator() -> surge_engine::audit::AuditActor {
    surge_engine::audit::AuditActor::Operator {
        name: std::env::var("USER").unwrap_or_else(|_| "unknown".into()),
    }
}
