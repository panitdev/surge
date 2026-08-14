//! The browser perimeter for `RemoteProvider`: a reverse proxy onto the
//! remote surge-server's own perimeter.
//!
//! The perimeter's policy (rate limits, flow state, CSRF) lives upstream,
//! where the database is. That makes this proxy part of upstream's trust
//! boundary rather than an anonymous client of it: it authenticates with a
//! service token and states the end user's address, so upstream can key
//! rate limits on the actual user instead of on this service. See
//! `trusted_proxy` for the receiving half.

use std::net::SocketAddr;
use std::sync::{Arc, Once};

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use tracing::warn;
use url::Url;

use super::cors;
use super::trusted_proxy::{CLIENT_IP_HEADER, SERVICE_TOKEN_HEADER};

/// Request headers passed through to upstream. An allowlist rather than a
/// denylist: anything the embedding application adds for its own purposes
/// is not upstream's business.
const FORWARDED_REQUEST_HEADERS: &[&str] = &["content-type", "accept", "x-surge-csrf"];

/// Only Surge's own cookies cross the boundary — the embedding
/// application's session, analytics, and consent cookies are none of
/// upstream's business, and the browser sends the whole jar regardless.
const FORWARDED_COOKIE_PREFIX: &str = "surge_";

/// Response headers dropped on the way back: hop-by-hop metadata that
/// described the upstream connection, not this one. `content-length` is
/// recomputed by axum from the body we actually emit.
const HOP_BY_HOP_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

const MAX_BODY_BYTES: usize = 1024 * 1024;

fn is_cors_header(name: &axum::http::HeaderName) -> bool {
    name == axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN
        || name == axum::http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS
        || name == axum::http::header::ACCESS_CONTROL_ALLOW_METHODS
        || name == axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS
        || name == axum::http::header::ACCESS_CONTROL_EXPOSE_HEADERS
        || name == axum::http::header::ACCESS_CONTROL_MAX_AGE
}

pub(crate) struct ProxyConfig {
    pub upstream_base_url: Url,
    pub cookie_domain: String,
    pub auth_ui_origin: String,
    pub session_cors_origins: Vec<String>,
    pub service_token: SecretString,
    pub client: Client,
}

pub(crate) fn proxy_browser_router(config: ProxyConfig) -> Router {
    let auth_ui_origin = config.auth_ui_origin.clone();
    let session_cors_origins = config.session_cors_origins.clone();

    let state = Arc::new(config);

    // Routes carry their `/v1` prefix literally instead of being nested
    // under it. Nesting strips the prefix from the request URI, and the
    // handler needs the path exactly as upstream expects to receive it.
    let credential_entry = Router::new()
        .route("/v1/login", get(proxy_handler))
        .route("/v1/flows/{id}", get(proxy_handler))
        .route("/v1/flows/{id}/password", post(proxy_handler))
        .route("/v1/flows/{id}/totp", post(proxy_handler))
        .route("/v1/flows/{id}/passphrase", post(proxy_handler))
        .route("/v1/flows/{id}/recover", post(proxy_handler))
        .route("/v1/flows/{id}/register", post(proxy_handler))
        .layer(cors::narrow(&auth_ui_origin))
        .with_state(Arc::clone(&state));

    let session_cors = if session_cors_origins.is_empty() {
        cors::narrow(&auth_ui_origin)
    } else {
        cors::union(&session_cors_origins)
    };

    let session_management = Router::new()
        .route("/v1/whoami", get(proxy_handler))
        .route("/v1/logout", post(proxy_handler))
        .route("/v1/factors", get(proxy_handler))
        .route("/v1/factors/totp/enroll", post(proxy_handler))
        .route("/v1/factors/totp/confirm", post(proxy_handler))
        .route("/v1/factors/totp", delete(proxy_handler))
        .route(
            "/v1/factors/passphrase",
            post(proxy_handler).delete(proxy_handler),
        )
        .route("/v1/factors/passphrase/confirm", post(proxy_handler))
        .route("/v1/account/password", post(proxy_handler))
        .layer(session_cors)
        .with_state(state);

    Router::new()
        .merge(credential_entry)
        .merge(session_management)
}

async fn proxy_handler(
    State(config): State<Arc<ProxyConfig>>,
    method: Method,
    // Deliberately the post-nesting URI, not `OriginalUri`: when the
    // application mounts this router under a prefix of its own
    // (`.nest("/api/surge", ..)`), that prefix is local addressing.
    // Upstream serves `/v1/...` and would 404 on `/api/surge/v1/...`.
    uri: Uri,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let upstream_url = format!(
        "{}{}",
        config.upstream_base_url.as_str().trim_end_matches('/'),
        path_and_query,
    );

    let Ok(upstream_method) = reqwest::Method::from_bytes(method.as_str().as_bytes()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut upstream_req = config.client.request(upstream_method, &upstream_url);

    for name in FORWARDED_REQUEST_HEADERS {
        if let Some(value) = headers.get(*name) {
            if let Ok(s) = value.to_str() {
                upstream_req = upstream_req.header(*name, s);
            }
        }
    }

    if let Some(cookies) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(surge_cookies)
    {
        upstream_req = upstream_req.header(axum::http::header::COOKIE, cookies);
    }

    // Proves to upstream that the `X-Surge-Client-Ip` below is a
    // statement it may trust. Note that neither header is forwarded from
    // the incoming request — a browser cannot smuggle either one through.
    upstream_req = upstream_req.header(
        SERVICE_TOKEN_HEADER,
        config.service_token.expose_secret(),
    );

    match peer_ip {
        Some(ip) => {
            upstream_req = upstream_req.header(CLIENT_IP_HEADER, ip.to_string());
        }
        // Without it, upstream keys every one of this service's users on
        // this service's own address, and one user's failed logins lock
        // out the rest. Serve with `into_make_service_with_connect_info`.
        None => warn_missing_connect_info(),
    }

    let body_bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes);
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, url = %upstream_url, "surge browser proxy request failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    let mut response_headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers() {
        // This hop has its own CORS zones, applied as a layer around this
        // handler; upstream's would collide with them.
        if is_cors_header(name) {
            continue;
        }
        if HOP_BY_HOP_RESPONSE_HEADERS.contains(&name.as_str()) {
            continue;
        }
        if name == axum::http::header::SET_COOKIE {
            if let Ok(s) = value.to_str() {
                let rewritten = rewrite_cookie_domain(s, &config.cookie_domain);
                if let Ok(v) = HeaderValue::from_str(&rewritten) {
                    response_headers.append(name.clone(), v);
                }
            }
            continue;
        }
        response_headers.append(name.clone(), value.clone());
    }

    let resp_body = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    (status, response_headers, resp_body).into_response()
}

/// The browser's address, when the server was bound with
/// `into_make_service_with_connect_info`. Never fails the request when it
/// wasn't — the proxy still works, it just cannot tell upstream who the
/// user is.
struct PeerIp(Option<std::net::IpAddr>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip()),
        ))
    }
}

fn warn_missing_connect_info() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        warn!(
            "surge browser proxy cannot see the client address: the server was not \
             bound with `into_make_service_with_connect_info::<SocketAddr>()`. Upstream \
             will rate-limit every user of this service under one bucket."
        );
    });
}

/// Narrows a `Cookie` header to Surge's own cookies. `None` when none are
/// present, so the header is dropped entirely rather than sent empty.
fn surge_cookies(cookie_header: &str) -> Option<String> {
    let kept: Vec<&str> = cookie_header
        .split(';')
        .map(str::trim)
        .filter(|pair| pair.starts_with(FORWARDED_COOKIE_PREFIX))
        .collect();

    if kept.is_empty() {
        None
    } else {
        Some(kept.join("; "))
    }
}

/// Re-scopes an upstream `Set-Cookie` onto the domain this proxy serves.
///
/// A cookie upstream left host-only stays host-only: it is already scoped
/// to this host once it arrives here, and adding a `Domain` would widen it
/// to every subdomain of `local_domain`.
fn rewrite_cookie_domain(set_cookie: &str, local_domain: &str) -> String {
    let mut result = String::with_capacity(set_cookie.len() + local_domain.len());

    for part in set_cookie.split(';') {
        if !result.is_empty() {
            result.push(';');
        }
        let trimmed = part.trim();
        if trimmed.to_ascii_lowercase().starts_with("domain=") {
            result.push_str(&format!(" Domain={local_domain}"));
        } else {
            result.push_str(part);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_domain_present() {
        let input = "surge_session=abc123; Domain=auth.example.com; Path=/; HttpOnly";
        let result = rewrite_cookie_domain(input, "app.example.com");
        assert!(result.contains("Domain=app.example.com"));
        assert!(!result.contains("auth.example.com"));
    }

    #[test]
    fn host_only_cookie_stays_host_only() {
        let input = "surge_session=abc123; Path=/; HttpOnly";
        let result = rewrite_cookie_domain(input, "app.example.com");
        assert_eq!(result, input);
    }

    #[test]
    fn cookie_jar_narrowed_to_surge_cookies() {
        let jar = "app_session=secret; surge_session=abc123; _ga=GA1.2.3";
        assert_eq!(surge_cookies(jar).as_deref(), Some("surge_session=abc123"));
    }

    #[test]
    fn cookie_header_dropped_when_no_surge_cookies() {
        assert!(surge_cookies("app_session=secret; _ga=GA1.2.3").is_none());
    }

    /// What upstream actually received, captured by a stand-in server.
    #[derive(Clone, Default)]
    struct Captured {
        path: String,
        headers: HeaderMap,
    }

    /// A stand-in surge-server that records one request and returns 204.
    async fn spawn_upstream() -> (Url, Arc<std::sync::Mutex<Captured>>) {
        let captured = Arc::new(std::sync::Mutex::new(Captured::default()));
        let sink = Arc::clone(&captured);

        let app = Router::new().fallback(move |uri: Uri, headers: HeaderMap| {
            let sink = Arc::clone(&sink);
            async move {
                *sink.lock().unwrap() = Captured {
                    path: uri.path_and_query().map(|p| p.to_string()).unwrap_or_default(),
                    headers,
                };
                StatusCode::NO_CONTENT
            }
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (
            Url::parse(&format!("http://{addr}")).unwrap(),
            captured,
        )
    }

    fn test_router(upstream: Url) -> Router {
        proxy_browser_router(ProxyConfig {
            upstream_base_url: upstream,
            cookie_domain: "app.example.com".into(),
            auth_ui_origin: "https://app.example.com".into(),
            session_cors_origins: vec![],
            service_token: SecretString::from("aeg_svc_test"),
            client: Client::new(),
        })
    }

    /// The application's own mount prefix is local addressing. Upstream
    /// serves `/v1/...` and 404s on anything else, so the prefix must not
    /// survive the hop.
    #[tokio::test]
    async fn mount_prefix_is_not_forwarded_upstream() {
        use tower::ServiceExt;

        let (upstream, captured) = spawn_upstream().await;
        let app = Router::new().nest("/api/surge", test_router(upstream));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/surge/v1/login?return_to=https://app.example.com/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            captured.lock().unwrap().path,
            "/v1/login?return_to=https://app.example.com/"
        );
    }

    #[tokio::test]
    async fn mounted_at_root_forwards_v1_unchanged() {
        use tower::ServiceExt;

        let (upstream, captured) = spawn_upstream().await;

        test_router(upstream)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/whoami")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(captured.lock().unwrap().path, "/v1/whoami");
    }

    /// Upstream keys rate limits on the address this header states, so a
    /// browser must not be able to supply either half of the claim.
    #[tokio::test]
    async fn proxy_authenticates_and_ignores_browser_supplied_claims() {
        use tower::ServiceExt;

        let (upstream, captured) = spawn_upstream().await;

        test_router(upstream)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/whoami")
                    .header(CLIENT_IP_HEADER, "9.9.9.9")
                    .header(SERVICE_TOKEN_HEADER, "aeg_svc_forged")
                    .header(axum::http::header::COOKIE, "app_sess=x; surge_session=abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let captured = captured.lock().unwrap();
        assert_eq!(
            captured.headers.get(SERVICE_TOKEN_HEADER).unwrap(),
            "aeg_svc_test"
        );
        // No ConnectInfo in a `oneshot` request, so no address is stated —
        // and the browser's own claim is not passed off as one.
        assert!(captured.headers.get(CLIENT_IP_HEADER).is_none());
        assert_eq!(
            captured.headers.get(axum::http::header::COOKIE).unwrap(),
            "surge_session=abc"
        );
    }

    /// `GET /v1/login` is answered by upstream with a redirect to the auth UI,
    /// and that redirect is for the *browser* to follow — it carries the flow id,
    /// and the auth UI must load under its own origin to resolve its assets.
    ///
    /// Built through `RemoteProvider` rather than `test_router` on purpose: the
    /// redirect policy lives on the client the provider constructs, so a router
    /// handed a test-local `Client::new()` would pass this while production
    /// silently followed the hop and served the auth UI's HTML as a 200.
    #[tokio::test]
    async fn upstream_redirect_reaches_the_browser() {
        use tower::ServiceExt;

        let app = Router::new().route(
            "/v1/login",
            get(|| async {
                (
                    StatusCode::SEE_OTHER,
                    [(
                        axum::http::header::LOCATION,
                        "https://auth.example.com/login?flow=aeg_f_test",
                    )],
                )
                    .into_response()
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let provider = std::sync::Arc::new(
            crate::remote::RemoteProvider::new(crate::RemoteConfig {
                base_url: Url::parse(&format!("http://{addr}")).unwrap(),
                service_token: SecretString::from("aeg_svc_test"),
                cache_ttl: std::time::Duration::from_secs(30),
                cache_max_entries: 10,
                timeout: std::time::Duration::from_secs(5),
            })
            .unwrap(),
        );

        let response = crate::traits::AuthProvider::browser_router(
            provider,
            crate::router::BrowserRouterConfig {
                cookie_domain: "app.example.com".into(),
                session_ttl: std::time::Duration::from_secs(3600),
                auth_ui_origin: "https://auth.example.com".into(),
                session_cors_origins: vec!["https://app.example.com".into()],
                rate_limiter: None,
                return_origins: None,
                registration: None,
                factor_policy: None,
                allow_inline: None,
                oauth_bridge: None,
                maintenance_interval: None,
            },
        )
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/login?return_to=https://app.example.com/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            "https://auth.example.com/login?flow=aeg_f_test"
        );
    }
}
