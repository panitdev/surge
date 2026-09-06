//! `POST /oauth2/register` — RFC 7591 dynamic client registration.
//!
//! Unauthenticated by specification, which makes it the largest abuse surface
//! in the AS. It is off unless the deployment turns it on, and everything it
//! can produce is deliberately bounded:
//!
//! - rate-limited per IP through the existing limiter;
//! - `registration_source='dynamic'`, `trust_state='untrusted'`,
//!   `first_party=false`, none of which this endpoint can set otherwise;
//! - scope capped by what registered resources declare — a client cannot
//!   invent a scope, only ask for one that already exists;
//! - redirect URIs `https`, or `http` on loopback for native clients;
//! - unused registrations swept after `SURGE_OAUTH_DCR_TTL_DAYS`.
//!
//! There is no registration access token and no RFC 7592 configuration
//! endpoint: a dynamic client that wants different metadata registers again.
//! That keeps a whole second credential lifecycle out of the design.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use surge_engine::oauth::{NewOauthClient, RegistrationSource};

use super::error::{OauthError, OauthErrorCode};
use super::AsState;
use crate::router::browser::MaybeClientIp;

#[derive(Debug, Deserialize)]
pub(crate) struct RegisterBody {
    client_name: Option<String>,
    client_uri: Option<String>,
    logo_uri: Option<String>,
    redirect_uris: Option<Vec<String>>,
    grant_types: Option<Vec<String>>,
    #[allow(dead_code)]
    response_types: Option<Vec<String>>,
    scope: Option<String>,
    token_endpoint_auth_method: Option<String>,
}

pub(crate) async fn register(
    State(state): State<Arc<AsState>>,
    MaybeClientIp(ip): MaybeClientIp,
    Json(body): Json<RegisterBody>,
) -> Response {
    match run(&state, ip, body).await {
        Ok(response) => response,
        Err(e) => e.into_response(),
    }
}

async fn run(
    state: &AsState,
    ip: Option<std::net::IpAddr>,
    body: RegisterBody,
) -> Result<Response, OauthError> {
    state
        .rate_limiter
        .check("oauth", "oauth_register", ip, None)
        .await
        .map_err(OauthError::from)?;

    let redirect_uris = body.redirect_uris.unwrap_or_default();
    if redirect_uris.is_empty() {
        return Err(OauthError::new(
            OauthErrorCode::InvalidRedirectUri,
            "redirect_uris is required and must contain at least one URI",
        ));
    }

    // Scopes are defined by resources. A dynamic client may ask for any scope
    // that already exists somewhere in the registry, and authorize narrows
    // that further per resource; it can never bring a new scope into being.
    let declared: std::collections::BTreeSet<String> = state
        .engine
        .list_oauth_resources()
        .await
        .map_err(OauthError::from)?
        .into_iter()
        .flat_map(|r| r.scopes)
        .collect();

    let requested: Vec<String> = body
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();

    let scopes: Vec<String> = if requested.is_empty() {
        declared.iter().cloned().collect()
    } else {
        let capped: Vec<String> = requested
            .into_iter()
            .filter(|s| declared.contains(s))
            .collect();
        if capped.is_empty() {
            return Err(OauthError::new(
                OauthErrorCode::InvalidClientMetadata,
                "none of the requested scopes are defined by any registered resource",
            ));
        }
        capped
    };

    // `client_secret_basic` is honoured; anything else falls back to a public
    // client, which is what MCP and native clients want anyway.
    let confidential = body.token_endpoint_auth_method.as_deref() == Some("client_secret_basic");

    let spec = NewOauthClient {
        client_name: body
            .client_name
            .unwrap_or_else(|| "Unnamed client".to_string()),
        client_uri: body.client_uri,
        logo_uri: body.logo_uri,
        redirect_uris: redirect_uris.clone(),
        grant_types: body
            .grant_types
            .filter(|g| !g.is_empty())
            .unwrap_or_else(|| {
                vec!["authorization_code".to_string(), "refresh_token".to_string()]
            }),
        scopes,
        confidential,
        // Not a parameter. A dynamically registered client is never
        // first-party, and the database refuses it independently.
        first_party: false,
        registration_source: RegistrationSource::Dynamic,
    };

    let (client, secret) = state
        .engine
        .create_oauth_client(spec)
        .await
        .map_err(|e| match e {
            surge_engine::AuthError::Validation(v) => {
                OauthError::new(OauthErrorCode::InvalidClientMetadata, v.to_string())
            }
            other => OauthError::from(other),
        })?;

    let mut response = json!({
        "client_id": client.client_id,
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
        "grant_types": client.grant_types,
        "response_types": ["code"],
        "scope": client.scopes.join(" "),
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "client_id_issued_at": client.created_at.timestamp(),
    });

    if let Some(secret) = secret {
        response["client_secret"] = json!(secret.expose_secret());
        // 0 means "does not expire" (RFC 7591 §3.2.1). Secrets here live as
        // long as the client does.
        response["client_secret_expires_at"] = json!(0);
    }

    Ok((StatusCode::CREATED, Json(response)).into_response())
}
