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

        match resolve_request_parts(provider, parts, true).await {
            Ok(resolved) => Ok(AuthSession(resolved.session)),
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
    cookie_authenticated: bool,
}

#[derive(Clone, Default)]
struct SessionCache(Vec<(Arc<dyn AuthProvider>, ResolvedSession)>);

pub(crate) async fn resolve_request_parts(
    provider: &Arc<dyn AuthProvider>,
    parts: &mut Parts,
    allow_bearer: bool,
) -> Result<ResolvedSession, AuthError> {
    if let Some(cache) = parts.extensions.get::<SessionCache>() {
        if let Some((_, resolved)) = cache.0.iter().find(|(source, resolved)| {
            Arc::ptr_eq(source, provider) && (allow_bearer || resolved.cookie_authenticated)
        }) {
            return Ok(resolved.clone());
        }
    }
    let resolved = resolve_request(provider.as_ref(), &parts.headers, allow_bearer).await?;
    parts
        .extensions
        .get_or_insert_default::<SessionCache>()
        .0
        .push((provider.clone(), resolved.clone()));
    Ok(resolved)
}

// Inspect the wire names before CookieJar drops undecodable values or fields.
pub(crate) fn browser_cookie(
    headers: &http::HeaderMap,
) -> Result<Option<BrowserSessionToken>, AuthError> {
    let mut found = None;
    for header in headers.get_all(http::header::COOKIE) {
        for pair in header.as_bytes().split(|byte| *byte == b';') {
            let mut fields = pair.trim_ascii().splitn(2, |byte| *byte == b'=');
            if fields.next().unwrap_or_default().trim_ascii() != BROWSER_COOKIE.as_bytes() {
                continue;
            }
            if found.is_some() {
                return Err(AuthError::InvalidToken);
            }
            let token = fields
                .next()
                .and_then(|raw| std::str::from_utf8(raw).ok())
                .and_then(BrowserSessionToken::from_raw)
                .ok_or(AuthError::InvalidToken)?;
            found = Some(token);
        }
    }
    Ok(found)
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
    if let Some(token) = browser_cookie(headers)? {
        let (account_id, session) = provider.resolve_browser_session(&token, selector).await?;
        return Ok(ResolvedSession {
            session,
            account_id: Some(account_id),
            cookie_authenticated: true,
        });
    }
    if selector.is_some() {
        return Err(AuthError::InvalidToken);
    }

    let (session, cookie_authenticated) = if let Some(cookie) = jar.get("surge_session") {
        match SessionToken::from_raw(cookie.value()) {
            Some(token) => (provider.verify_browser_cookie(token).await?, true),
            None if allow_bearer => (provider.verify_session(None).await?, false),
            None => return Err(AuthError::InvalidToken),
        }
    } else if allow_bearer {
        let token = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .and_then(SessionToken::from_raw);
        (provider.verify_session(token).await?, false)
    } else {
        return Err(AuthError::InvalidToken);
    };
    Ok(ResolvedSession {
        session,
        account_id: None,
        cookie_authenticated,
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
        for browser in ["invalid", "", "%ff"] {
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
    #[tokio::test]
    async fn malformed_browser_fields_override_legacy_credentials() {
        let provider = TestProvider::new(TestConfig::default()).unwrap();
        for bad in [b"surge_browser".as_slice(), b"surge_browser=\xff"] {
            let mut headers = http::HeaderMap::new();
            headers.append(
                http::header::COOKIE,
                format!("surge_session={}", SessionToken::generate().expose_secret())
                    .parse()
                    .unwrap(),
            );
            headers.append(
                http::header::COOKIE,
                http::HeaderValue::from_bytes(bad).unwrap(),
            );
            assert!(matches!(
                resolve_request(&provider, &headers, true).await,
                Err(AuthError::InvalidToken)
            ));
        }
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "surge_session=malformed".parse().unwrap(),
        );
        assert!(resolve_request(&provider, &headers, true).await.is_ok());
        assert!(resolve_request(&provider, &headers, false).await.is_err());
    }

    #[tokio::test]
    async fn cached_selection_is_scoped_to_provider_and_credential_kind() {
        let first: Arc<dyn AuthProvider> =
            Arc::new(TestProvider::new(TestConfig::default()).unwrap());
        let second: Arc<dyn AuthProvider> =
            Arc::new(TestProvider::new(TestConfig::default()).unwrap());
        let token = SessionToken::generate();
        let (mut parts, _) = http::Request::builder()
            .header(
                http::header::AUTHORIZATION,
                format!("Bearer {}", token.expose_secret()),
            )
            .body(())
            .unwrap()
            .into_parts();
        resolve_request_parts(&first, &mut parts, true)
            .await
            .unwrap();
        assert!(resolve_request_parts(&first, &mut parts, false)
            .await
            .is_err());

        let (mut parts, _) = http::Request::builder()
            .header(
                http::header::COOKIE,
                format!("surge_session={}", token.expose_secret()),
            )
            .body(())
            .unwrap()
            .into_parts();
        let a = resolve_request_parts(&first, &mut parts, true)
            .await
            .unwrap();
        let b = resolve_request_parts(&second, &mut parts, false)
            .await
            .unwrap();
        assert_ne!(a.session.id, b.session.id);
        let again = resolve_request_parts(&first, &mut parts, false)
            .await
            .unwrap();
        assert_eq!(again.session.issued_at, a.session.issued_at);
    }
}
