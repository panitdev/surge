//! Browser-bound, single-use account selection for validated OAuth requests.
use super::{
    AsState,
    authorize::{AuthorizeQuery, authorize_query, resolve_authorization_session},
};
use crate::router::error::ApiError;
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use std::sync::Arc;
use surge_engine::{AuthError, SessionToken, oauth::ChooserCredential};
use uuid::Uuid;

fn chooser_credential(headers: &HeaderMap) -> Result<Option<ChooserCredential>, AuthError> {
    if let Some(token) = crate::extract::browser_cookie(headers)? {
        return Ok(Some(ChooserCredential::Browser(token)));
    }
    Ok(CookieJar::from_headers(headers)
        .get("surge_session")
        .and_then(|c| SessionToken::from_raw(c.value()))
        .map(ChooserCredential::Legacy))
}

pub(super) async fn start_request(
    state: &AsState,
    headers: &HeaderMap,
    query: &AuthorizeQuery,
    resource: &str,
    scopes: &[String],
    force_picker: bool,
) -> Result<Response, ApiError> {
    let existing = match chooser_credential(headers)? {
        Some(ChooserCredential::Legacy(token)) => match state.engine.verify_session(&token).await {
            Ok(_) => Some(ChooserCredential::Legacy(token)),
            Err(
                AuthError::InvalidToken | AuthError::SessionExpired | AuthError::IdentityDisabled,
            ) => None,
            Err(e) => return Err(e.into()),
        },
        existing => existing,
    };
    let mut jar = CookieJar::new();
    let token = match existing {
        Some(token) => token,
        None => {
            let browser = state.engine.create_chooser_browser().await?;
            let mut cookie = super::super::cookie::session_cookie(
                browser.token.expose_secret(),
                &state.cookie_domain,
                (browser.expires_at - chrono::Utc::now()).num_seconds(),
            );
            cookie.set_name(crate::extract::BROWSER_COOKIE);
            jar = jar.add(cookie);
            ChooserCredential::Browser(browser.token)
        }
    };
    let mut payload = serde_json::to_value(query).map_err(|e| AuthError::Internal(e.into()))?;
    payload["scope"] = scopes.join(" ").into();
    payload["resource"] = resource.into();
    let id = state.engine.save_chooser_request(&token, payload).await?;
    let ui = state.config.auth_ui_origin.trim_end_matches('/');
    let target = if force_picker
        || match &token {
            ChooserCredential::Browser(token) => !state
                .engine
                .list_browser_accounts(token)
                .await?
                .accounts
                .is_empty(),
            ChooserCredential::Legacy(_) => true,
        } {
        format!("{ui}/choose-account?request_id={id}")
    } else {
        chooser_login_url(state, &token, &id).await?
    };
    Ok((jar, Redirect::to(&target)).into_response())
}

async fn chooser_login_url(
    state: &AsState,
    token: &ChooserCredential,
    id: &str,
) -> Result<String, ApiError> {
    let resume = state.endpoint(&format!("/v1/oauth/authorization-requests/{id}/resume"));
    let flow = state.engine.start_chooser_login(token, id, &resume).await?;
    Ok(format!(
        "{}/login?flow={flow}",
        state.config.auth_ui_origin.trim_end_matches('/')
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Choice {
    account_id: Option<Uuid>,
    use_another_account: Option<bool>,
    use_current_account: Option<bool>,
}

pub(crate) async fn choose_account(
    State(state): State<Arc<AsState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(choice): Json<Choice>,
) -> Result<Response, ApiError> {
    let token = chooser_credential(&headers)?.ok_or(AuthError::InvalidToken)?;
    let target = match (
        choice.account_id,
        choice.use_another_account,
        choice.use_current_account,
        &token,
    ) {
        (Some(_), None, None, ChooserCredential::Browser(_))
        | (None, None, Some(true), ChooserCredential::Legacy(_)) => {
            let selected =
                resolve_authorization_session(&state, &headers, choice.account_id).await?;
            let (payload, _) = state
                .engine
                .take_chooser_request(&token, &id, false)
                .await?;
            let query =
                serde_json::from_value(payload).map_err(|e| AuthError::Internal(e.into()))?;
            let response = authorize_query(&state, query, &headers, None, Some(selected)).await;
            let Some(location) = response.headers().get(axum::http::header::LOCATION) else {
                return Ok(response);
            };
            location
                .to_str()
                .map_err(|e| AuthError::Internal(e.into()))?
                .to_owned()
        }
        (None, Some(true), None, _) => chooser_login_url(&state, &token, &id).await?,
        _ => {
            return Err(AuthError::Validation(surge_engine::ValidationError::Field {
                field: "account_id",
                message: "choose one account or use another account".into(),
            })
            .into());
        }
    };
    Ok(Json(serde_json::json!({"redirect_to":target})).into_response())
}

pub(crate) async fn resume_login(
    State(state): State<Arc<AsState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = crate::extract::browser_cookie(&headers)?.ok_or(AuthError::InvalidToken)?;
    let (payload, session) = state
        .engine
        .take_chooser_request(&ChooserCredential::Browser(token.clone()), &id, true)
        .await?;
    let expected = session.ok_or(AuthError::InvalidToken)?;
    let account = state.engine.account_for_session(&token, expected).await?;
    let selected = resolve_authorization_session(&state, &headers, Some(account)).await?;
    if *selected.0.id.as_uuid() != expected {
        return Err(AuthError::InvalidToken.into());
    }
    let query = serde_json::from_value(payload).map_err(|e| AuthError::Internal(e.into()))?;
    Ok(authorize_query(&state, query, &headers, None, Some(selected)).await)
}
