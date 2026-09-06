//! RFC 8414 authorization-server metadata and the JWKS document.
//!
//! This document is the indirection a `/vN` path prefix would otherwise
//! provide: clients read `token_endpoint` rather than hardcoding a path, so
//! the endpoints below are free to move as long as this stays accurate.

use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use super::error::OauthError;
use super::AsState;

pub(crate) async fn metadata(State(state): State<Arc<AsState>>) -> Response {
    // Advertised scopes are the union of what registered resources define.
    // Scopes belong to resources, so this is derived rather than configured —
    // there is no list an operator could get out of sync.
    let scopes = match state.engine.list_oauth_resources().await {
        Ok(resources) => {
            let mut scopes: Vec<String> = resources
                .into_iter()
                .flat_map(|r| r.scopes)
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            if state.config.enable_oidc {
                scopes.push("openid".to_string());
                scopes.push("profile".to_string());
            }
            scopes
        }
        Err(e) => return OauthError::from(e).into_response(),
    };

    let mut doc = json!({
        "issuer": state.issuer(),
        "authorization_endpoint": state.endpoint("/oauth2/authorize"),
        "token_endpoint": state.endpoint("/oauth2/token"),
        "jwks_uri": state.endpoint("/oauth2/jwks.json"),
        "introspection_endpoint": state.endpoint("/oauth2/introspect"),
        "revocation_endpoint": state.endpoint("/oauth2/revoke"),
        "scopes_supported": scopes,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        // S256 only. Advertising `plain` would invite clients to use it.
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_basic",
            "client_secret_post"
        ],
        // RFC 8707: every token this server issues is audience-restricted.
        "resource_indicators_supported": true,
        "authorization_response_iss_parameter_supported": false,
        "service_documentation": "https://github.com/panit/surge",
    });

    if state.config.enable_oidc {
        doc["userinfo_endpoint"] = json!(state.endpoint("/oauth2/userinfo"));
        doc["subject_types_supported"] = json!(["public"]);
        doc["id_token_signing_alg_values_supported"] = json!(["ES256"]);
        doc["claims_supported"] = json!([
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "nonce",
            "preferred_username",
            "name",
            "picture"
        ]);
    }

    if state.config.allow_dynamic_registration {
        doc["registration_endpoint"] = json!(state.endpoint("/oauth2/register"));
    }

    Json(doc).into_response()
}

/// The active key plus any retired keys still inside their grace window, so a
/// token signed moments before a rotation keeps verifying until it expires.
pub(crate) async fn jwks(State(state): State<Arc<AsState>>) -> Response {
    match state.engine.public_oauth_signing_keys().await {
        Ok(keys) => {
            let jwks = json!({
                "keys": keys.into_iter().map(|k| k.public_jwk).collect::<Vec<_>>(),
            });
            let mut response = Json(jwks).into_response();
            response.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("public, max-age=300"),
            );
            response
        }
        Err(e) => OauthError::from(e).into_response(),
    }
}
