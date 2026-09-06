//! The consent flow's browser API (`/v1/oauth/consent/{flow_id}`).
//!
//! Consent-screen quality is a security control, not polish. The single most
//! likely way this design fails in practice is a screen that presents a
//! dynamically registered client's self-declared name the same way it
//! presents a verified first-party one, training people to approve anything.
//! So the GET response states, in a field the UI cannot miss, whether the
//! client registered itself — and the UI **must** render that distinction.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::json;
use surge_engine::oauth::{AuthorizationGrant, RegistrationSource};
use surge_engine::AuthError;

use super::authorize::{current_session, issue_code_redirect};
use super::error::{build_redirect, OauthErrorCode};
use super::AsState;
use crate::router::error::ApiError;

pub(crate) async fn get_consent_flow(
    State(state): State<Arc<AsState>>,
    Path(flow_id): Path<String>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let flow = state.engine.get_consent_flow(&flow_id).await?;

    // The flow belongs to whoever was signed in when it was created. Reading
    // it as anyone else would leak which apps another person is connecting.
    let session = current_session(&state, &jar)
        .await
        .ok_or(AuthError::InvalidToken)?;
    if session.identity.id != flow.identity_id {
        return Err(AuthError::Forbidden.into());
    }

    let client = state.engine.get_oauth_client(&flow.client_id).await?;
    let resource = state.engine.get_oauth_resource(&flow.resource_uri).await?;

    let scopes: Vec<serde_json::Value> = flow
        .scopes
        .iter()
        .map(|scope| {
            let description = resource
                .scope_descriptions
                .get(scope)
                .and_then(|v| v.as_str())
                .map(str::to_string);
            json!({ "scope": scope, "description": description })
        })
        .collect();

    Ok(Json(json!({
        "flow_id": flow.id,
        "csrf_token": flow.csrf_token,
        "client": {
            "client_id": client.client_id,
            "client_name": client.client_name,
            "client_uri": client.client_uri,
            "logo_uri": client.logo_uri,
            // The bit the screen must not bury: a dynamically registered
            // client's name and logo are attacker-supplied text and an
            // attacker-supplied image.
            "dynamically_registered":
                client.registration_source == RegistrationSource::Dynamic,
            "first_party": client.first_party,
        },
        "resource": {
            "resource_uri": resource.resource_uri,
        },
        "scopes": scopes,
        "expires_at": flow.expires_at,
    }))
    .into_response())
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConsentDecision {
    approve: bool,
    /// The scopes actually approved. Absent means "all of the requested
    /// ones"; anything outside the requested set is rejected rather than
    /// silently dropped, because a UI sending unrequested scopes is a bug
    /// worth hearing about.
    scopes: Option<Vec<String>>,
    csrf_token: String,
}

pub(crate) async fn decide_consent_flow(
    State(state): State<Arc<AsState>>,
    Path(flow_id): Path<String>,
    jar: CookieJar,
    Json(decision): Json<ConsentDecision>,
) -> Result<Response, ApiError> {
    let flow = state.engine.get_consent_flow(&flow_id).await?;

    let session = current_session(&state, &jar)
        .await
        .ok_or(AuthError::InvalidToken)?;
    if session.identity.id != flow.identity_id {
        return Err(AuthError::Forbidden.into());
    }
    crate::router::csrf::check_flow_csrf(&flow.csrf_token, &decision.csrf_token)?;

    if !decision.approve {
        // Denial is an answer, so the flow is spent either way.
        state.engine.decide_consent_flow(&flow_id).await?;
        let redirect = build_redirect(&flow.redirect_uri, |q| {
            q.append_pair("error", OauthErrorCode::AccessDenied.as_str());
            q.append_pair("error_description", "the user denied this request");
            if let Some(state) = flow.state.as_deref() {
                q.append_pair("state", state);
            }
        })
        .ok_or_else(|| AuthError::Internal(anyhow::anyhow!("unparseable redirect_uri")))?;

        return Ok(Json(json!({ "redirect_to": redirect })).into_response());
    }

    let approved = match decision.scopes {
        Some(scopes) => {
            if !scopes.iter().all(|s| flow.scopes.contains(s)) {
                return Err(AuthError::Validation(surge_engine::ValidationError::Field {
                    field: "scopes",
                    message: "approved scopes must be a subset of the requested ones".into(),
                })
                .into());
            }
            scopes
        }
        None => flow.scopes.clone(),
    };

    // Consume the flow before minting anything: an approve that could be
    // replayed is a code-minting oracle.
    let flow = state.engine.decide_consent_flow(&flow_id).await?;

    state
        .engine
        .record_consent(
            &flow.client_id,
            flow.identity_id,
            &flow.resource_uri,
            approved.clone(),
        )
        .await?;

    let grant = AuthorizationGrant {
        client_id: flow.client_id.clone(),
        identity_id: flow.identity_id,
        session_id: flow.session_id,
        resource_uri: flow.resource_uri.clone(),
        redirect_uri: flow.redirect_uri.clone(),
        scopes: approved,
        code_challenge: flow.code_challenge.clone(),
        code_challenge_method: flow.code_challenge_method.clone(),
        nonce: flow.nonce.clone(),
    };

    // The UI navigates the browser itself, so the redirect target comes back
    // as JSON rather than as a 303 the fetch() would have to follow.
    let response = issue_code_redirect(&state, &grant, flow.state.as_deref())
        .await
        .map_err(|e| AuthError::Internal(anyhow::anyhow!(e)))?;

    let redirect_to = response
        .headers()
        .get(axum::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| AuthError::Internal(anyhow::anyhow!("no redirect target was built")))?;

    Ok(Json(json!({ "redirect_to": redirect_to })).into_response())
}
