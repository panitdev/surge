use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
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
