//! `POST /oauth2/token` — the back channel.
//!
//! Two grant types, and no others. No client credentials (there is no user to
//! scope a token to), no password grant (OAuth 2.1 removed it, and Surge
//! already has a first-party login surface for that shape), no device code
//! until something actually needs it.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;
use serde_json::json;
use surge_engine::oauth::{verify_pkce, OauthClient, RefreshGrant};
use surge_engine::{AuthError, AuthorizationCode, ClientSecret, RefreshToken};

use super::error::{OauthError, OauthErrorCode};
use super::jwt::{self, AccessTokenSpec, IdClaims};
use super::AsState;

#[derive(Debug, Deserialize)]
pub(crate) struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
}

pub(crate) async fn token(
    State(state): State<Arc<AsState>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    match dispatch(&state, &headers, form).await {
        Ok(response) => response,
        Err(e) => e.into_response(),
    }
}

async fn dispatch(
    state: &AsState,
    headers: &HeaderMap,
    form: TokenForm,
) -> Result<Response, OauthError> {
    let client = authenticate_client(state, headers, &form).await?;

    match form.grant_type.as_deref() {
        Some("authorization_code") => authorization_code_grant(state, client, form).await,
        Some("refresh_token") => refresh_token_grant(state, client, form).await,
        Some(other) => Err(OauthError::new(
            OauthErrorCode::UnsupportedGrantType,
            format!("unsupported grant_type: {other}"),
        )),
        None => Err(OauthError::new(
            OauthErrorCode::InvalidRequest,
            "grant_type is required",
        )),
    }
}

/// Client authentication. A confidential client must present its secret (HTTP
/// Basic per RFC 6749 §2.3.1, or `client_secret_post`); a public client
/// identifies itself with `client_id` alone and is safe to do so only because
/// PKCE binds the code to the requester.
async fn authenticate_client(
    state: &AsState,
    headers: &HeaderMap,
    form: &TokenForm,
) -> Result<OauthClient, OauthError> {
    let basic = basic_auth(headers);
    let client_id = basic
        .as_ref()
        .map(|(id, _)| id.clone())
        .or_else(|| form.client_id.clone())
        .ok_or_else(|| {
            OauthError::new(OauthErrorCode::InvalidClient, "client_id is required")
        })?;

    let secret = basic
        .as_ref()
        .and_then(|(_, secret)| secret.clone())
        .or_else(|| form.client_secret.clone());

    let client = state.engine.get_oauth_client(&client_id).await.map_err(|e| {
        match e {
            AuthError::NotFound => {
                OauthError::new(OauthErrorCode::InvalidClient, "unknown client")
            }
            other => OauthError::from(other),
        }
    })?;

    match (client.confidential, secret) {
        (true, Some(secret)) => {
            let parsed = ClientSecret::from_raw(&secret).ok_or_else(|| {
                OauthError::new(OauthErrorCode::InvalidClient, "client authentication failed")
            })?;
            state
                .engine
                .verify_client_secret(&client_id, &parsed)
                .await
                .map_err(|_| {
                    OauthError::new(OauthErrorCode::InvalidClient, "client authentication failed")
                })
        }
        (true, None) => Err(OauthError::new(
            OauthErrorCode::InvalidClient,
            "this client is confidential and must authenticate",
        )),
        // A public client presenting a secret is a misconfiguration worth
        // surfacing, not something to quietly accept.
        (false, Some(_)) => Err(OauthError::new(
            OauthErrorCode::InvalidClient,
            "this client is registered as public and must not present a client secret",
        )),
        (false, None) => Ok(client),
    }
}

async fn authorization_code_grant(
    state: &AsState,
    client: OauthClient,
    form: TokenForm,
) -> Result<Response, OauthError> {
    let code = form
        .code
        .as_deref()
        .and_then(AuthorizationCode::from_raw)
        .ok_or_else(|| OauthError::new(OauthErrorCode::InvalidGrant, "invalid code"))?;

    let verifier = form.code_verifier.as_deref().ok_or_else(|| {
        OauthError::new(OauthErrorCode::InvalidRequest, "code_verifier is required")
    })?;

    // Redeems atomically; a second presentation of the same code fails here.
    let grant = state
        .engine
        .consume_authorization_code(&code, &client.client_id)
        .await
        .map_err(|_| {
            OauthError::new(
                OauthErrorCode::InvalidGrant,
                "the code is unknown, expired, already redeemed, or was issued to another client",
            )
        })?;

    // RFC 6749 §4.1.3: the redirect URI presented here must match the one the
    // code was issued against, which is what stops a code stolen by one
    // registered redirect from being redeemed against another.
    if form.redirect_uri.as_deref() != Some(grant.redirect_uri.as_str()) {
        return Err(OauthError::new(
            OauthErrorCode::InvalidGrant,
            "redirect_uri does not match the one this code was issued for",
        ));
    }

    if !verify_pkce(&grant.code_challenge, &grant.code_challenge_method, verifier) {
        return Err(OauthError::new(
            OauthErrorCode::InvalidGrant,
            "PKCE verification failed",
        ));
    }

    // RFC 8707 §2.2: if the client narrows the audience at the token
    // endpoint, it may only name the one the code was issued for.
    if let Some(requested) = form.resource.as_deref() {
        let canonical = surge_engine::oauth::canonicalize_resource_uri(requested)
            .map_err(|e| OauthError::new(OauthErrorCode::InvalidTarget, e.to_string()))?;
        if canonical != grant.resource_uri {
            return Err(OauthError::new(
                OauthErrorCode::InvalidTarget,
                "resource does not match the audience this code was issued for",
            ));
        }
    }

    let refresh_grant = RefreshGrant {
        client_id: grant.client_id.clone(),
        identity_id: grant.identity_id,
        session_id: grant.session_id,
        resource_uri: grant.resource_uri.clone(),
        scopes: grant.scopes.clone(),
        family_id: uuid::Uuid::new_v4(),
    };

    issue_token_response(state, &client, &refresh_grant, grant.nonce.as_deref(), true).await
}

async fn refresh_token_grant(
    state: &AsState,
    client: OauthClient,
    form: TokenForm,
) -> Result<Response, OauthError> {
    let token = form
        .refresh_token
        .as_deref()
        .and_then(RefreshToken::from_raw)
        .ok_or_else(|| OauthError::new(OauthErrorCode::InvalidGrant, "invalid refresh token"))?;

    let rotated = state
        .engine
        .rotate_refresh_token(&token, &client.client_id, state.config.refresh_ttl)
        .await
        .map_err(|_| {
            OauthError::new(
                OauthErrorCode::InvalidGrant,
                "the refresh token is unknown, expired, revoked, or has already been used",
            )
        })?;

    // The grant is bound to the identity, so this is the check that matters:
    // a disabled account stops refreshing within one access-token lifetime,
    // with no resource server changing anything (internal/oauth-as.md §7).
    let identity = state
        .provider
        .identity(rotated.grant.identity_id)
        .await
        .map_err(|_| {
            OauthError::new(OauthErrorCode::InvalidGrant, "the account is no longer active")
        })?;
    if identity.state != surge_engine::IdentityState::Active {
        return Err(OauthError::new(
            OauthErrorCode::InvalidGrant,
            "the account is disabled",
        ));
    }

    // A refresh may narrow scope but never widen it (RFC 6749 §6).
    let mut grant = rotated.grant;
    if let Some(requested) = form.scope.as_deref() {
        let requested: Vec<String> = requested.split_whitespace().map(str::to_string).collect();
        if !requested.iter().all(|s| grant.scopes.contains(s)) {
            return Err(OauthError::new(
                OauthErrorCode::InvalidScope,
                "a refresh may narrow the granted scope but never widen it",
            ));
        }
        if !requested.is_empty() {
            grant.scopes = requested;
        }
    }

    let response = build_token_body(state, &client, &grant, None, false).await?;
    Ok(Json(with_refresh(response, rotated.token.expose_secret())).into_response())
}

/// Mints the access token (and, when in play, the ID token) plus a fresh
/// refresh token for a brand-new grant.
async fn issue_token_response(
    state: &AsState,
    client: &OauthClient,
    grant: &RefreshGrant,
    nonce: Option<&str>,
    issue_refresh: bool,
) -> Result<Response, OauthError> {
    let body = build_token_body(state, client, grant, nonce, true).await?;

    if !issue_refresh {
        return Ok(Json(body).into_response());
    }

    let refresh = state
        .engine
        .issue_refresh_token(grant, state.config.refresh_ttl)
        .await
        .map_err(OauthError::from)?;

    Ok(Json(with_refresh(body, refresh.expose_secret())).into_response())
}

async fn build_token_body(
    state: &AsState,
    client: &OauthClient,
    grant: &RefreshGrant,
    nonce: Option<&str>,
    include_id_token: bool,
) -> Result<serde_json::Value, OauthError> {
    let key = state
        .engine
        .active_oauth_signing_key()
        .await
        .map_err(OauthError::from)?;

    let subject = grant.identity_id.to_string();
    let minted = jwt::sign_access_token(
        &key,
        AccessTokenSpec {
            issuer: state.issuer(),
            subject: &subject,
            audience: &grant.resource_uri,
            client_id: &client.client_id,
            scopes: &grant.scopes,
            session_id: &grant.session_id.to_string(),
            ttl: state.config.access_ttl,
        },
    )?;

    let mut body = json!({
        "access_token": minted.token,
        "token_type": "Bearer",
        "expires_in": minted.expires_in,
        "scope": grant.scopes.join(" "),
    });

    let wants_openid = state.config.enable_oidc && grant.scopes.iter().any(|s| s == "openid");
    if wants_openid && include_id_token {
        let identity = state
            .provider
            .identity(grant.identity_id)
            .await
            .map_err(OauthError::from)?;
        let now = chrono::Utc::now().timestamp();
        let id_token = jwt::sign_id_token(
            &key,
            IdClaims {
                iss: state.issuer().to_string(),
                sub: subject.clone(),
                aud: client.client_id.clone(),
                iat: now,
                exp: now + state.config.access_ttl.as_secs() as i64,
                nonce: nonce.map(str::to_string),
                preferred_username: Some(identity.username.as_str().to_string()),
                name: Some(identity.display_name.clone()),
                picture: identity.avatar_url.as_ref().map(|u| u.to_string()),
            },
        )?;
        body["id_token"] = json!(id_token);
    }

    Ok(body)
}

fn with_refresh(mut body: serde_json::Value, refresh: &str) -> serde_json::Value {
    body["refresh_token"] = json!(refresh);
    body
}

/// RFC 6749 §2.3.1 HTTP Basic client authentication. The credentials are
/// form-urlencoded before base64, which is easy to forget and produces
/// baffling failures for clients whose secrets contain reserved characters.
pub(super) fn basic_auth(headers: &HeaderMap) -> Option<(String, Option<String>)> {
    use base64::Engine as _;

    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(raw.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;

    let (id, secret) = match decoded.split_once(':') {
        Some((id, secret)) => (id, Some(secret)),
        None => (decoded.as_str(), None),
    };

    Some((form_decode(id), secret.map(form_decode)))
}

/// Percent-decoding for one Basic-auth component. `+` is a space and `%XX` is
/// a byte; anything malformed is left verbatim rather than dropped, so a
/// secret that was never encoded in the first place still compares equal.
fn form_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_decodes_the_rfc_6749_encoding() {
        use base64::Engine as _;

        let raw = base64::engine::general_purpose::STANDARD
            .encode("aeg_cid_abc:aeg_cs_x%2Fy+z");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Basic {raw}").parse().unwrap(),
        );

        let (id, secret) = basic_auth(&headers).unwrap();
        assert_eq!(id, "aeg_cid_abc");
        assert_eq!(secret.as_deref(), Some("aeg_cs_x/y z"));
    }

    #[test]
    fn a_missing_or_malformed_basic_header_is_not_an_identity() {
        assert!(basic_auth(&HeaderMap::new()).is_none());

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer aeg_s_whatever".parse().unwrap(),
        );
        assert!(basic_auth(&headers).is_none());
    }
}
