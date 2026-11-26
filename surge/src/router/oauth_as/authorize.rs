//! `GET /oauth2/authorize` — the front channel.
//!
//! Order matters here more than anywhere else in the AS. The client and its
//! `redirect_uri` are validated *first*, because every later error is
//! delivered by redirecting to that URI, and redirecting to an unvalidated
//! one is the open-redirect this endpoint is most likely to become.

use std::sync::Arc;

use super::chooser::start_request;
use super::cimd::CimdError;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use surge_engine::oauth::{
    AuthorizationGrant, AuthorizationSession, ConsentFlowRequest, OauthClient, OauthResource,
    canonicalize_resource_uri, cimd_client_may_use_resource, client_may_use_resource,
};
use surge_engine::{AuthError, Session, SessionToken};

use super::AsState;
use super::error::{
    OauthErrorCode, authorize_error_page, authorize_error_redirect, build_redirect,
};

#[derive(Debug, Deserialize, Serialize)]
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
    /// Browser-local selector supplied by an account-pinned application.
    pub account_id: Option<String>,
    pub prompt: Option<String>,
}

pub(crate) async fn authorize(
    State(state): State<Arc<AsState>>,
    query: Result<Query<AuthorizeQuery>, axum::extract::rejection::QueryRejection>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    // Unparseable, or a parameter given twice (RFC 6749 §3.1). Nothing here
    // is trustworthy yet, so the error is shown, never redirected.
    let Query(query) = match query {
        Ok(query) => query,
        Err(rejection) => {
            return authorize_error_page(OauthErrorCode::InvalidRequest, &rejection.body_text());
        }
    };
    authorize_query(&state, query, &headers, Some(uri), None, None).await
}

pub(super) async fn authorize_query(
    state: &AsState,
    query: AuthorizeQuery,
    headers: &HeaderMap,
    original: Option<axum::http::Uri>,
    selected: Option<(Session, AuthorizationSession)>,
    // A resumed account choice is bound to the registration it was first
    // validated against; a replacement at the same URI is not that resource.
    registration: Option<uuid::Uuid>,
) -> Response {
    // --- Phase 1: nothing may be redirected anywhere yet. ---
    let Some(client_id) = query.client_id.as_deref() else {
        return authorize_error_page(OauthErrorCode::InvalidRequest, "client_id is required");
    };

    // A client ID that is an `https://` URL names a metadata document (CIMD);
    // every registered client has a generated `aeg_cid_…` ID.
    let (client, cimd) = if client_id.starts_with("https://") {
        match resolve_cimd_client(state, client_id, query.resource.as_deref()).await {
            Ok((client, metadata)) => (client, Some(metadata)),
            Err(response) => return *response,
        }
    } else {
        match state.engine.get_oauth_client(client_id).await {
            Ok(client) => (client, None),
            Err(AuthError::NotFound) => {
                return authorize_error_page(OauthErrorCode::InvalidClient, "unknown client");
            }
            Err(e) => return authorize_error_page(OauthErrorCode::ServerError, &e.to_string()),
        }
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

    let identity_only = state.config.enable_oidc
        && cimd.is_none()
        && query.resource.is_none()
        && query
            .scope
            .as_deref()
            .is_some_and(|scope| scope.split_whitespace().eq(["openid"]));
    let resource = if identity_only {
        state
            .engine
            .oauth_userinfo_resource()
            .await
            .map_err(|e| (OauthErrorCode::ServerError, e.to_string()))
    } else {
        resolve_resource(state, query.resource.as_deref()).await
    };
    let resource = match resource {
        Ok(resource) => resource,
        Err((code, message)) => return fail(code, &message),
    };
    if registration.is_some_and(|id| id != resource.registration_id) {
        return fail(
            OauthErrorCode::InvalidTarget,
            "the resource was registered again since this request began; authorize again",
        );
    }

    if !client_may_use_resource(&client, &resource, state.engine.eligibility_policy()) {
        return fail(OauthErrorCode::InvalidTarget, INELIGIBLE_TARGET);
    }

    let scopes = match resolve_scopes(query.scope.as_deref(), &client, &resource) {
        Ok(scopes) => scopes,
        Err(message) => return fail(OauthErrorCode::InvalidScope, &message),
    };

    let prompts: Vec<_> = query
        .prompt
        .as_deref()
        .unwrap_or_default()
        .split_ascii_whitespace()
        .collect();
    let picker = prompts.contains(&"select_account");
    let silent = prompts.contains(&"none");
    if silent && prompts.len() != 1 {
        return fail(
            OauthErrorCode::InvalidRequest,
            "prompt=none cannot be combined with another prompt",
        );
    }
    if query.account_id.is_some() && picker {
        return fail(
            OauthErrorCode::InvalidRequest,
            "account_id conflicts with prompt=select_account",
        );
    }
    let selector = match query.account_id.as_deref().map(str::parse).transpose() {
        Ok(value) => value,
        Err(_) => {
            return fail(
                OauthErrorCode::LoginRequired,
                "requested account is unavailable",
            );
        }
    };
    let chooser_error = |error: crate::router::error::ApiError| {
        if cimd.is_some()
            && let Some((code, message)) = admission_refusal(&error.0)
        {
            return fail(code, message);
        }
        error.into_response()
    };
    if original.is_some() && picker {
        if !state.multi_account {
            return fail(
                OauthErrorCode::InvalidRequest,
                "account selection is unavailable",
            );
        }
        return start_request(state, headers, &query, &resource, &scopes, true)
            .await
            .unwrap_or_else(chooser_error);
    }
    let resolved = match selected {
        Some(selected) => Ok(selected),
        None => resolve_authorization_session(state, headers, selector).await,
    };
    let (session, binding) = match resolved {
        Ok(selected) => selected,
        Err(AuthError::InvalidToken | AuthError::SessionExpired | AuthError::IdentityDisabled) => {
            if query.account_id.is_some() || silent {
                return fail(
                    OauthErrorCode::LoginRequired,
                    "requested account is unavailable",
                );
            }
            if state.multi_account {
                return start_request(state, headers, &query, &resource, &scopes, false)
                    .await
                    .unwrap_or_else(chooser_error);
            }
            let Some(uri) = original else {
                return fail(OauthErrorCode::LoginRequired, "session expired");
            };
            let self_url = format!("{}{}", state.issuer(), uri);
            let login = format!(
                "{}/v1/login?return_to={}",
                state.issuer(),
                percent_encode(&self_url)
            );
            return Redirect::to(&login).into_response();
        }
        Err(error) => return fail(OauthErrorCode::ServerError, &error.to_string()),
    };

    // --- Phase 4: consent. ---
    let needs_consent = if client.first_party {
        false
    } else {
        match state
            .engine
            .find_consent(
                &client.client_id,
                session.identity.id,
                resource.registration_id,
            )
            .await
        {
            Ok(Some(consent)) => !scopes.iter().all(|s| consent.scopes.contains(s)),
            Ok(None) => true,
            Err(e) => return fail(OauthErrorCode::ServerError, &e.to_string()),
        }
    };

    if needs_consent {
        if silent {
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
                account_id: binding.account_id(),
                registration_id: resource.registration_id,
                resource_uri: resource.resource_uri.clone(),
                scopes: scopes.clone(),
                redirect_uri: redirect_uri.to_string(),
                state: query.state.clone(),
                nonce: query.nonce.clone(),
                code_challenge: code_challenge.to_string(),
                code_challenge_method: "S256".to_string(),
                // Stores the shared client row in the flow's transaction,
                // after the session, document and eligibility checks above.
                cimd: cimd.clone(),
            })
            .await
        {
            Ok(flow) => flow,
            Err(e) => {
                return match admission_refusal(&e) {
                    Some((code, message)) => fail(code, message),
                    None => fail(OauthErrorCode::ServerError, &e.to_string()),
                };
            }
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
        registration_id: resource.registration_id,
        resource_uri: resource.resource_uri,
        redirect_uri: redirect_uri.to_string(),
        scopes,
        code_challenge: code_challenge.to_string(),
        code_challenge_method: "S256".to_string(),
        nonce: query.nonce.clone(),
    };

    match issue_code_redirect(state, &grant, &binding, None, query.state.as_deref()).await {
        Ok(response) => response,
        Err(AuthError::InvalidToken) => fail(
            OauthErrorCode::LoginRequired,
            "requested account is unavailable",
        ),
        Err(error) => match admission_refusal(&error) {
            Some((code, message)) => fail(code, message),
            None => fail(OauthErrorCode::ServerError, &error.to_string()),
        },
    }
}

/// Turns a CIMD client ID into the in-memory client the request is evaluated
/// as. Nothing is stored here: the row is written when the consent flow is
/// created, once every other check has passed.
///
/// Resource policy and revocation are checked before any metadata fetch.
/// Every refusal here is an error page, not a redirect: until
/// the document is verified there is no redirect URI to trust.
async fn resolve_cimd_client(
    state: &AsState,
    client_id: &str,
    requested_resource: Option<&str>,
) -> Result<(OauthClient, surge_engine::oauth::CimdMetadata), Box<Response>> {
    let page = |code, message: &str| Box::new(authorize_error_page(code, message));
    if let Err(reason) = surge_engine::oauth::validate_cimd_client_id(client_id) {
        return Err(page(OauthErrorCode::InvalidClient, reason));
    }
    let resource = match resolve_resource(state, requested_resource).await {
        Ok(resource) => resource,
        Err((code, message)) => return Err(page(code, &message)),
    };
    if !cimd_client_may_use_resource(client_id, &resource) {
        return Err(page(OauthErrorCode::InvalidTarget, INELIGIBLE_TARGET));
    }
    // A revoked client stays revoked, whatever its document now says.
    match state.engine.cimd_client_is_revoked(client_id).await {
        Ok(false) => {}
        Ok(true) => return Err(page(OauthErrorCode::InvalidClient, "unknown client")),
        Err(e) => return Err(page(OauthErrorCode::ServerError, &e.to_string())),
    }
    match state.cimd.resolve(client_id).await {
        Ok(metadata) => Ok((OauthClient::from_cimd(&metadata, &resource), metadata)),
        Err(CimdError::Invalid(reason)) => Err(page(
            OauthErrorCode::InvalidClient,
            &format!("the client metadata document is not acceptable: {reason}"),
        )),
        Err(CimdError::Unavailable | CimdError::RateLimited) => Err(page(
            OauthErrorCode::TemporarilyUnavailable,
            "the client metadata document is temporarily unavailable",
        )),
    }
}

/// How the engine's under-lock eligibility re-check refuses (a policy change
/// landed after the checks above): the same answers those checks give.
pub(crate) fn admission_refusal(e: &AuthError) -> Option<(OauthErrorCode, &'static str)> {
    match e {
        AuthError::Forbidden | AuthError::NotFound => {
            Some((OauthErrorCode::InvalidTarget, INELIGIBLE_TARGET))
        }
        AuthError::ConsentRequired => Some((
            OauthErrorCode::ConsentRequired,
            "the saved approval no longer covers this request; authorize again",
        )),
        AuthError::ScopeNotGranted => Some((
            OauthErrorCode::InvalidScope,
            "the resource no longer offers a requested scope",
        )),
        _ => None,
    }
}

/// The one message for every ineligible target. It does not say whether the
/// resource exists, is delegated, or is merely not approved for this client.
pub(crate) const INELIGIBLE_TARGET: &str =
    "this client is not permitted to request tokens for the requested resource";

/// Mints a code and builds the success redirect. Shared with the consent
/// decision endpoint, which reaches this point by a different road.
pub(crate) async fn issue_code_redirect(
    state: &AsState,
    grant: &AuthorizationGrant,
    binding: &AuthorizationSession,
    consent_flow: Option<&str>,
    oauth_state: Option<&str>,
) -> Result<Response, AuthError> {
    let code = state
        .engine
        .mint_authorization_code(grant, binding, consent_flow)
        .await?;

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
    .ok_or_else(|| {
        AuthError::Internal(anyhow::anyhow!("registered redirect_uri failed to parse"))
    })?;

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
        // Indistinguishable from an ineligible target.
        Err(AuthError::NotFound) => {
            Err((OauthErrorCode::InvalidTarget, INELIGIBLE_TARGET.to_string()))
        }
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
    // Explicit ceiling: the client's list ∩ the resource's current scopes.
    // Registered without scopes: whatever the resource currently permits.
    let grantable = surge_engine::oauth::permitted_scopes(client, resource);

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

pub(crate) async fn resolve_authorization_session(
    state: &AsState,
    headers: &axum::http::HeaderMap,
    selector: Option<uuid::Uuid>,
) -> Result<(Session, AuthorizationSession), AuthError> {
    if let Some(token) = crate::extract::browser_cookie(headers)? {
        let (account_id, session) = state
            .provider
            .resolve_browser_session(&token, selector)
            .await?;
        return Ok((session, AuthorizationSession::Member(token, account_id)));
    }
    if selector.is_some() {
        return Err(AuthError::InvalidToken);
    }
    let jar = CookieJar::from_headers(headers);
    let token = jar
        .get("surge_session")
        .and_then(|cookie| SessionToken::from_raw(cookie.value()))
        .ok_or(AuthError::InvalidToken)?;
    let session = state.provider.verify_browser_cookie(token.clone()).await?;
    Ok((session, AuthorizationSession::Legacy(token)))
}

pub(crate) fn percent_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
