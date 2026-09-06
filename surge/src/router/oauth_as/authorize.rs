//! `GET /oauth2/authorize` — the front channel.
//!
//! Order matters here more than anywhere else in the AS. The client and its
//! `redirect_uri` are validated *first*, because every later error is
//! delivered by redirecting to that URI, and redirecting to an unvalidated
//! one is the open-redirect this endpoint is most likely to become.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use surge_engine::oauth::{
    canonicalize_resource_uri, AuthorizationGrant, ConsentFlowRequest, OauthClient, OauthResource,
};
use surge_engine::{AuthError, Session, SessionToken};

use super::error::{authorize_error_page, authorize_error_redirect, build_redirect, OauthErrorCode};
use super::AsState;

#[derive(Debug, Deserialize)]
pub(crate) struct AuthorizeQuery {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub resource: Option<String>,
    pub nonce: Option<String>,
    /// OIDC `prompt`. Only `none` is honoured, and only to refuse: a client
    /// that asks for no interaction gets `login_required` or
    /// `consent_required` rather than a screen.
    pub prompt: Option<String>,
}

pub(crate) async fn authorize(
    State(state): State<Arc<AsState>>,
    Query(query): Query<AuthorizeQuery>,
    jar: CookieJar,
    uri: axum::http::Uri,
) -> Response {
    // --- Phase 1: nothing may be redirected anywhere yet. ---
    let Some(client_id) = query.client_id.as_deref() else {
        return authorize_error_page(OauthErrorCode::InvalidRequest, "client_id is required");
    };

    let client = match state.engine.get_oauth_client(client_id).await {
        Ok(client) => client,
        Err(AuthError::NotFound) => {
            return authorize_error_page(OauthErrorCode::InvalidClient, "unknown client");
        }
        Err(e) => return authorize_error_page(OauthErrorCode::ServerError, &e.to_string()),
    };

    let Some(redirect_uri) = query.redirect_uri.as_deref() else {
        return authorize_error_page(
            OauthErrorCode::InvalidRequest,
            "redirect_uri is required; this server does not infer one",
        );
    };

    // Exact match, byte for byte. Prefix and pattern matching are how open
    // redirects get introduced with the best of intentions.
    if !client.redirect_uris.iter().any(|u| u == redirect_uri) {
        return authorize_error_page(
            OauthErrorCode::InvalidRedirectUri,
            "redirect_uri does not exactly match a registered URI for this client",
        );
    }

    // --- Phase 2: the client is verified; errors now go to its redirect. ---
    let fail = |code, description: &str| {
        authorize_error_redirect(redirect_uri, code, description, query.state.as_deref())
    };

    if query.response_type.as_deref() != Some("code") {
        return fail(
            OauthErrorCode::UnsupportedResponseType,
            "only response_type=code is supported (OAuth 2.1 removed the implicit flow)",
        );
    }

    // PKCE is mandatory and S256-only. `plain` is not merely unsupported: it
    // provides no protection against a code intercepted in the redirect,
    // which is the entire threat PKCE addresses.
    let Some(code_challenge) = query.code_challenge.as_deref().filter(|c| !c.is_empty()) else {
        return fail(
            OauthErrorCode::InvalidRequest,
            "code_challenge is required (PKCE S256)",
        );
    };
    if query.code_challenge_method.as_deref() != Some("S256") {
        return fail(
            OauthErrorCode::InvalidRequest,
            "code_challenge_method must be S256",
        );
    }

    let resource = match resolve_resource(&state, query.resource.as_deref()).await {
        Ok(resource) => resource,
        Err((code, message)) => return fail(code, &message),
    };

    let scopes = match resolve_scopes(query.scope.as_deref(), &client, &resource) {
        Ok(scopes) => scopes,
        Err(message) => return fail(OauthErrorCode::InvalidScope, &message),
    };

    // --- Phase 3: who is this? ---
    //
    // Re-checked on every authorize rather than trusting any remembered
    // state, exactly as the Hydra bridge does. The bounce carries a
    // `return_to` pointing back at this same URL, so the round-trip re-enters
    // here once `surge_session` is set.
    let session = match current_session(&state, &jar).await {
        Some(session) => session,
        None => {
            if query.prompt.as_deref() == Some("none") {
                return fail(
                    OauthErrorCode::LoginRequired,
                    "no active session and prompt=none was requested",
                );
            }
            let self_url = format!("{}{}", state.issuer(), uri);
            let login = format!(
                "{}/v1/login?return_to={}",
                state.issuer(),
                percent_encode(&self_url)
            );
            return Redirect::to(&login).into_response();
        }
    };

    // --- Phase 4: consent. ---
    let needs_consent = if client.first_party {
        false
    } else {
        match state
            .engine
            .find_consent(&client.client_id, session.identity.id, &resource.resource_uri)
            .await
        {
            Ok(Some(consent)) => !scopes.iter().all(|s| consent.scopes.contains(s)),
            Ok(None) => true,
            Err(e) => return fail(OauthErrorCode::ServerError, &e.to_string()),
        }
    };

    if needs_consent {
        if query.prompt.as_deref() == Some("none") {
            return fail(
                OauthErrorCode::ConsentRequired,
                "this client needs the user's approval and prompt=none was requested",
            );
        }

        let flow = match state
            .engine
            .create_consent_flow(ConsentFlowRequest {
                client_id: client.client_id.clone(),
                identity_id: session.identity.id,
                session_id: *session.id.as_uuid(),
                resource_uri: resource.resource_uri.clone(),
                scopes: scopes.clone(),
                redirect_uri: redirect_uri.to_string(),
                state: query.state.clone(),
                nonce: query.nonce.clone(),
                code_challenge: code_challenge.to_string(),
                code_challenge_method: "S256".to_string(),
            })
            .await
        {
            Ok(flow) => flow,
            Err(e) => return fail(OauthErrorCode::ServerError, &e.to_string()),
        };

        let consent_url = format!(
            "{}/consent?consent_flow={}",
            state.config.auth_ui_origin.trim_end_matches('/'),
            percent_encode(&flow.id)
        );
        return Redirect::to(&consent_url).into_response();
    }

    // --- Phase 5: mint. ---
    let grant = AuthorizationGrant {
        client_id: client.client_id.clone(),
        identity_id: session.identity.id,
        session_id: *session.id.as_uuid(),
        resource_uri: resource.resource_uri,
        redirect_uri: redirect_uri.to_string(),
        scopes,
        code_challenge: code_challenge.to_string(),
        code_challenge_method: "S256".to_string(),
        nonce: query.nonce.clone(),
    };

    match issue_code_redirect(&state, &grant, query.state.as_deref()).await {
        Ok(response) => response,
        Err(message) => fail(OauthErrorCode::ServerError, &message),
    }
}

/// Mints a code and builds the success redirect. Shared with the consent
/// decision endpoint, which reaches this point by a different road.
pub(crate) async fn issue_code_redirect(
    state: &AsState,
    grant: &AuthorizationGrant,
    oauth_state: Option<&str>,
) -> Result<Response, String> {
    let code = state
        .engine
        .mint_authorization_code(grant)
        .await
        .map_err(|e| e.to_string())?;

    // Best-effort: this only feeds the unused-client sweep, and failing an
    // otherwise-good authorization over it would be absurd.
    if let Err(e) = state.engine.touch_oauth_client(&grant.client_id).await {
        tracing::warn!(error = %e, client_id = %grant.client_id, "failed to record client use");
    }

    let url = build_redirect(&grant.redirect_uri, |q| {
        q.append_pair("code", code.expose_secret());
        if let Some(state) = oauth_state {
            q.append_pair("state", state);
        }
    })
    .ok_or_else(|| "registered redirect_uri failed to parse".to_string())?;

    Ok(Redirect::to(&url).into_response())
}

/// Resolves the RFC 8707 `resource` parameter against the audience registry.
async fn resolve_resource(
    state: &AsState,
    requested: Option<&str>,
) -> Result<OauthResource, (OauthErrorCode, String)> {
    let uri = match requested {
        Some(uri) => Some(uri.to_string()),
        None if state.config.require_resource => {
            return Err((
                OauthErrorCode::InvalidTarget,
                "the resource parameter is required (RFC 8707); tokens here are always \
                 audience-restricted"
                    .to_string(),
            ));
        }
        None => state.config.default_resource.clone(),
    };

    let Some(uri) = uri else {
        return Err((
            OauthErrorCode::InvalidTarget,
            "no resource was requested and this deployment has no default audience".to_string(),
        ));
    };

    let canonical = canonicalize_resource_uri(&uri)
        .map_err(|e| (OauthErrorCode::InvalidTarget, e.to_string()))?;

    match state.engine.get_oauth_resource(&canonical).await {
        Ok(resource) => Ok(resource),
        Err(AuthError::NotFound) => Err((
            OauthErrorCode::InvalidTarget,
            "unknown resource; this audience is not registered with this authorization server"
                .to_string(),
        )),
        Err(e) => Err((OauthErrorCode::ServerError, e.to_string())),
    }
}

/// Requested scopes must be within both what the client may ever be granted
/// and what the resource actually defines. Scopes are defined by resources,
/// never invented by clients — which is what keeps the scope space from
/// growing one entry per integration.
pub(crate) fn resolve_scopes(
    requested: Option<&str>,
    client: &OauthClient,
    resource: &OauthResource,
) -> Result<Vec<String>, String> {
    let grantable: Vec<String> = resource
        .scopes
        .iter()
        .filter(|s| client.scopes.iter().any(|c| c == *s))
        .cloned()
        .collect();

    let requested: Vec<String> = requested
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();

    if requested.is_empty() {
        if grantable.is_empty() {
            return Err(
                "this client has no scopes in common with the requested resource".to_string(),
            );
        }
        return Ok(grantable);
    }

    // `openid` is not a resource scope — it is a request for an ID token, and
    // it never appears in `oauth_resource.scopes`.
    for scope in &requested {
        if scope == "openid" || scope == "profile" || scope == "offline_access" {
            continue;
        }
        if !grantable.contains(scope) {
            return Err(format!(
                "scope `{scope}` is not granted to this client for this resource"
            ));
        }
    }

    Ok(requested)
}

pub(crate) async fn current_session(state: &AsState, jar: &CookieJar) -> Option<Session> {
    let cookie = jar.get("surge_session")?;
    let token = SessionToken::from_raw(cookie.value())?;
    state.provider.verify_session(Some(token)).await.ok()
}

pub(crate) fn percent_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
