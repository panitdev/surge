use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
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

        match provider.verify_session(extract_token(parts)).await {
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

fn extract_token(parts: &Parts) -> Option<SessionToken> {
    let jar = CookieJar::from_headers(&parts.headers);
    if let Some(cookie) = jar.get("surge_session") {
        return SessionToken::from_raw(cookie.value());
    }

    let auth = parts.headers.get("authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    SessionToken::from_raw(token)
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

