use std::sync::Arc;

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;

use crate::traits::AuthProvider;
use crate::*;

pub struct AuthSession(pub Session);

#[derive(Debug)]
pub enum AuthRejection {
    Unauthorized(String),
    ServiceUnavailable(String),
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg).into_response(),
            Self::ServiceUnavailable(msg) => {
                (StatusCode::SERVICE_UNAVAILABLE, msg).into_response()
            }
        }
    }
}

impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync + AsRef<Arc<dyn AuthProvider>>,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let provider: &Arc<dyn AuthProvider> = state.as_ref();

        let token = extract_token(parts);

        let token = match token {
            Some(raw) => SessionToken::from_raw(&raw)
                .ok_or_else(|| AuthRejection::Unauthorized("invalid token format".into()))?,
            None => return Err(AuthRejection::Unauthorized("no session token".into())),
        };

        match provider.verify_session(&token).await {
            Ok(session) => Ok(AuthSession(session)),
            Err(AuthError::InvalidToken | AuthError::SessionExpired) => {
                Err(AuthRejection::Unauthorized("invalid or expired session".into()))
            }
            Err(AuthError::IdentityDisabled) => {
                Err(AuthRejection::Unauthorized("identity disabled".into()))
            }
            Err(AuthError::Unavailable | AuthError::Timeout) => Err(
                AuthRejection::ServiceUnavailable("auth service unavailable".into()),
            ),
            Err(_) => Err(AuthRejection::ServiceUnavailable(
                "internal auth error".into(),
            )),
        }
    }
}

fn extract_token(parts: &Parts) -> Option<String> {
    let jar = CookieJar::from_headers(&parts.headers);
    if let Some(cookie) = jar.get("surge_session") {
        return Some(cookie.value().to_string());
    }

    let auth = parts.headers.get("authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    Some(token.to_string())
}

/// Cheap anti-CSRF gate for cookie-authenticated, state-changing endpoints:
/// requires `X-Surge-CSRF: 1`. A cross-origin form post or plain `<img>`/
/// navigation can't set a custom header, so this alone blocks classic CSRF
/// without needing a token round-trip. Combine with CORS, not instead of it.
pub async fn require_header_csrf(
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, AuthRejection> {
    let ok = req
        .headers()
        .get("x-surge-csrf")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "1");

    if !ok {
        return Err(AuthRejection::Unauthorized("missing X-Surge-CSRF header".into()));
    }
    Ok(next.run(req).await)
}

/// The default, same-origin session-resolution path (§8.5): a service
/// nests this to get `GET /me` and `POST /logout` backed directly by the
/// extractor, without ever routing the browser to Surge. Revocation is
/// global (`revoke_session`), and the cookie is cleared for `cookie_domain`.
pub fn me_logout_router<S>(cookie_domain: impl Into<String>) -> Router<S>
where
    S: Clone + Send + Sync + AsRef<Arc<dyn AuthProvider>> + 'static,
{
    let cookie_domain = cookie_domain.into();
    Router::new().route("/me", get(me)).route(
        "/logout",
        post(move |State(state): State<S>, jar: CookieJar| {
            let cookie_domain = cookie_domain.clone();
            async move { logout(state, jar, cookie_domain).await }
        }),
    )
}

async fn me(AuthSession(session): AuthSession) -> impl IntoResponse {
    Json(serde_json::to_value(&session).unwrap())
}

async fn logout<S>(
    state: S,
    jar: CookieJar,
    cookie_domain: String,
) -> Result<impl IntoResponse, AuthRejection>
where
    S: AsRef<Arc<dyn AuthProvider>>,
{
    let provider: &Arc<dyn AuthProvider> = state.as_ref();

    if let Some(raw) = jar.get("surge_session").map(|c| c.value().to_string()) {
        if let Some(token) = SessionToken::from_raw(&raw) {
            let _ = provider.revoke_session(&token).await;
        }
    }

    let removal = Cookie::build(("surge_session", ""))
        .domain(cookie_domain)
        .path("/")
        .max_age(time::Duration::ZERO)
        .http_only(true)
        .secure(true)
        .build();

    Ok((jar.add(removal), StatusCode::NO_CONTENT))
}
