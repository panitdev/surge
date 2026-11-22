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
/// the referrer origin or, without a referrer, the trusted mount origin.
pub(crate) fn list_origin(
    headers: &http::HeaderMap,
    uri: &http::Uri,
    public_origin: Option<&str>,
) -> Option<String> {
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
        if !headers.contains_key(http::header::REFERER) {
            // Fetch Metadata establishes the same-origin relationship. The
            // configured mount supplies the scheme and authority; Host alone
            // (or forwarding headers from the caller) cannot grant access.
            let configured = public_origin?;
            let url = url::Url::parse(configured).ok()?;
            if !matches!(url.scheme(), "http" | "https")
                || url.origin().ascii_serialization() != configured
            {
                return None;
            }
            let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
            let host = if headers.contains_key(http::header::HOST) {
                Some(single(headers, "host")?)
            } else {
                None
            };
            let target = uri.authority().map(|value| value.as_str());
            if host.or(target).is_none()
                || host.into_iter().chain(target).any(|value| !value.eq_ignore_ascii_case(authority))
                || uri.scheme_str().is_some_and(|scheme| scheme != url.scheme())
            {
                return None;
            }
            return Some(configured.to_owned());
        }
        single(headers, "referer")?
    };
    let url = url::Url::parse(source).ok()?;
    let origin = url.origin().ascii_serialization();
    (matches!(url.scheme(), "http" | "https") && (!explicit || origin == source)).then_some(origin)
}

#[cfg(test)]
mod tests {
    use super::list_origin;
    use http::{HeaderMap, HeaderValue, Uri};

    #[test]
    fn referrerless_listing_requires_a_trusted_matching_origin() {
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        headers.insert("x-forwarded-host", HeaderValue::from_static("app.example"));
        let path = Uri::from_static("/v1/accounts");
        let origin = Some("https://app.example");
        assert!(list_origin(&headers, &path, origin).is_none());
        let absolute = Uri::from_static("https://app.example/v1/accounts");
        assert_eq!(list_origin(&headers, &absolute, origin).as_deref(), origin);
        assert!(list_origin(&headers, &absolute, None).is_none());
        headers.insert("host", HeaderValue::from_static("other.example"));
        assert!(list_origin(&headers, &absolute, origin).is_none());
        headers.insert("host", HeaderValue::from_static("app.example"));
        headers.insert("origin", HeaderValue::from_static("null"));
        assert!(list_origin(&headers, &path, origin).is_none());
    }
}
