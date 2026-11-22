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
            Self::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg).into_response(),
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

        if let Some(resolved) = parts.extensions.get::<ResolvedSession>() {
            return Ok(AuthSession(resolved.session.clone()));
        }
        match resolve_request(provider.as_ref(), &parts.headers, true).await {
            Ok(resolved) => {
                let session = resolved.session.clone();
                parts.extensions.insert(resolved);
                Ok(AuthSession(session))
            }
            Err(AuthError::InvalidToken | AuthError::SessionExpired) => Err(
                AuthRejection::Unauthorized("invalid or expired session".into()),
            ),
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

pub(crate) const ACCOUNT_HEADER: &str = "x-surge-account";
pub(crate) const BROWSER_COOKIE: &str = "surge_browser";

#[derive(Clone)]
pub(crate) struct ResolvedSession {
    pub session: Session,
    pub account_id: Option<uuid::Uuid>,
}

pub(crate) async fn resolve_request(
    provider: &dyn AuthProvider,
    headers: &http::HeaderMap,
    allow_bearer: bool,
) -> Result<ResolvedSession, AuthError> {
    let jar = CookieJar::from_headers(headers);
    let mut selectors = headers.get_all(ACCOUNT_HEADER).iter();
    let selector = selectors
        .next()
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or(AuthError::InvalidToken)
        })
        .transpose()?;
    if selectors.next().is_some() {
        return Err(AuthError::InvalidToken);
    }
    if let Some(cookie) = jar.get(BROWSER_COOKIE) {
        let token = BrowserSessionToken::from_raw(cookie.value()).ok_or(AuthError::InvalidToken)?;
        let (account_id, session) = provider.resolve_browser_session(&token, selector).await?;
        return Ok(ResolvedSession {
            session,
            account_id: Some(account_id),
        });
    }
    if selector.is_some() {
        return Err(AuthError::InvalidToken);
    }

    let token = if let Some(cookie) = jar.get("surge_session") {
        Some(SessionToken::from_raw(cookie.value()).ok_or(AuthError::InvalidToken)?)
    } else if allow_bearer {
        headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .and_then(SessionToken::from_raw)
    } else {
        return Err(AuthError::InvalidToken);
    };
    let session = provider.verify_session(token).await?;
    Ok(ResolvedSession {
        session,
        account_id: None,
    })
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
        return Err(AuthRejection::Unauthorized(
            "missing X-Surge-CSRF header".into(),
        ));
    }
    Ok(next.run(req).await)
}

#[cfg(all(test, feature = "test-provider"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalid_browser_credentials_and_selectors_fail_closed() {
        let provider = TestProvider::new(TestConfig::default()).unwrap();
        let mut headers = http::HeaderMap::new();
        let legacy = SessionToken::generate();
        let cookie = format!("surge_session={}", legacy.expose_secret());
        headers.insert(http::header::COOKIE, cookie.parse().unwrap());
        assert!(resolve_request(&provider, &headers, false).await.is_ok());
        for browser in ["invalid", ""] {
            headers.insert(
                http::header::COOKIE,
                format!("{cookie}; {BROWSER_COOKIE}={browser}")
                    .parse()
                    .unwrap(),
            );
            assert!(matches!(
                resolve_request(&provider, &headers, false).await,
                Err(AuthError::InvalidToken)
            ));
        }
        headers.insert(http::header::COOKIE, cookie.parse().unwrap());
        headers.insert(
            ACCOUNT_HEADER,
            uuid::Uuid::nil().to_string().parse().unwrap(),
        );
        assert!(matches!(
            resolve_request(&provider, &headers, false).await,
            Err(AuthError::InvalidToken)
        ));
    }
}
