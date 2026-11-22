use http::header::HeaderName;
use tower_http::cors::{AllowOrigin, CorsLayer};

static CSRF_HEADER: HeaderName = HeaderName::from_static("x-surge-csrf");

fn base() -> CorsLayer {
    CorsLayer::new()
        .allow_credentials(true)
        .allow_methods([http::Method::GET, http::Method::POST, http::Method::DELETE])
        .allow_headers([
            http::header::CONTENT_TYPE,
            http::header::COOKIE,
            CSRF_HEADER.clone(),
        ])
}

/// Single-origin CORS zone (credential-entry default; session-management
/// default when `session_cors_origins` is empty).
pub(crate) fn narrow(origin: &str) -> CorsLayer {
    match origin.parse() {
        Ok(value) => base().allow_origin(AllowOrigin::exact(value)),
        Err(_) => base().allow_origin(AllowOrigin::list(Vec::new())),
    }
}

/// Credentialed CORS over the union of registered return origins — the
/// opt-in browser->Surge session-management zone (§8.2b).
pub(crate) fn union(origins: &[String]) -> CorsLayer {
    let parsed = origins.iter().filter_map(|o| o.parse().ok()).collect::<Vec<_>>();
    base().allow_origin(AllowOrigin::list(parsed))
}

pub(crate) fn account_scoped(layer: CorsLayer) -> CorsLayer {
    let selector = HeaderName::from_static(crate::extract::ACCOUNT_HEADER);
    layer
        .allow_methods([http::Method::GET, http::Method::POST, http::Method::PUT, http::Method::DELETE])
        .allow_headers([http::header::CONTENT_TYPE, http::header::COOKIE, CSRF_HEADER.clone(), selector.clone()])
        .expose_headers([selector])
}

/// Browsers can omit Origin on a same-origin GET. In that case use only
/// the origin of the browser-supplied referrer, never its path or query.
pub(crate) fn list_origin(headers: &http::HeaderMap) -> Option<String> {
    fn single<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
        let mut values = headers.get_all(name).iter();
        let value = values.next()?.to_str().ok()?;
        values.next().is_none().then_some(value)
    }
    let explicit = headers.contains_key(http::header::ORIGIN);
    let source = if explicit {
        single(headers, "origin")?
    } else {
        if single(headers, "sec-fetch-site")? != "same-origin" {
            return None;
        }
        single(headers, "referer")?
    };
    let url = url::Url::parse(source).ok()?;
    let origin = url.origin().ascii_serialization();
    (matches!(url.scheme(), "http" | "https") && (!explicit || origin == source)).then_some(origin)
}
