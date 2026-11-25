//! Fetching client-ID metadata documents (CIMD) from the network.
//!
//! The URL comes from an unauthenticated authorization request, so this is
//! the most SSRF-exposed code in the server. Defence is layered, and each
//! layer assumes the one before it failed:
//!
//! 1. The authorize handler only reaches here for a URL that the target
//!    resource's allowlist names exactly, so strangers cannot aim the server
//!    at arbitrary hosts.
//! 2. [`validate_cimd_client_id`] admits only canonical `https` URLs naming a
//!    public-looking DNS host: no IP literals, userinfo, fragments or
//!    explicit ports.
//! 3. [`PublicOnlyResolver`] resolves the host and refuses the *whole*
//!    lookup if any returned address is not publicly routable. The connector
//!    dials only the addresses that resolver returned, so a name that
//!    resolves differently a moment later cannot redirect the connection
//!    (DNS rebinding), and TLS still verifies the certificate against the
//!    original host name.
//! 4. No redirects, no proxy (a proxy would dial for us and bypass 3), no
//!    cookies, no compression, bounded time and size, and a JSON content
//!    type.
//!
//! On top sits [`CimdResolver`]: a bounded cache honouring `Cache-Control`
//! (clamped), negative caching of failures, a per-host rate limit and a cap
//! on concurrent fetches, so a flood of requests cannot turn this server
//! into a traffic source.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use surge_engine::oauth::{
    parse_cimd_document, validate_cimd_client_id, CimdMetadata, MAX_CIMD_DOCUMENT_BYTES,
};
use tokio::sync::Semaphore;
use tokio::time::Instant;

/// A fetched document, before it is validated.
#[derive(Debug, Clone)]
pub struct FetchedDocument {
    pub body: Vec<u8>,
    /// How long the origin allows the document to be reused: `None` when it
    /// said nothing, `Some(ZERO)` for `no-store`/`no-cache`.
    pub max_age: Option<Duration>,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct FetchError(pub String);

/// Retrieves the document at a (validated) client ID URL. The production
/// implementation is [`HttpDocumentFetcher`]; tests inject their own.
#[async_trait]
pub trait CimdDocumentFetcher: Send + Sync {
    async fn fetch(&self, url: &url::Url) -> Result<FetchedDocument, FetchError>;
}

/// Stands in when the HTTP client cannot be built: every fetch fails.
pub(super) struct UnavailableFetcher;

#[async_trait]
impl CimdDocumentFetcher for UnavailableFetcher {
    async fn fetch(&self, _: &url::Url) -> Result<FetchedDocument, FetchError> {
        Err(FetchError("no HTTP client".into()))
    }
}

// ---------------------------------------------------------------------------
// Address policy
// ---------------------------------------------------------------------------

/// True only for addresses that are globally routable unicast. Everything
/// special-purpose is refused: loopback, private (RFC 1918), shared/CGNAT,
/// link-local, unique-local, multicast, broadcast, unspecified,
/// documentation, benchmarking, reserved, and every IPv6 form that embeds an
/// IPv4 address (mapped, compatible, NAT64, 6to4, Teredo), which would let a
/// private IPv4 destination ride in on an IPv6 literal.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0                                   // 0.0.0.0/8 "this network"
        || a == 10                             // RFC 1918
        || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10 CGNAT
        || a == 127                            // loopback
        || (a == 169 && b == 254)              // link-local
        || (a == 172 && (16..=31).contains(&b)) // RFC 1918
        || (a == 192 && b == 0 && c == 0)      // 192.0.0.0/24 IETF protocol
        || (a == 192 && b == 0 && c == 2)      // TEST-NET-1
        || (a == 192 && b == 88 && c == 99)    // 6to4 relay anycast
        || (a == 192 && b == 168)              // RFC 1918
        || (a == 198 && (b == 18 || b == 19))  // benchmarking
        || (a == 198 && b == 51 && c == 100)   // TEST-NET-2
        || (a == 203 && b == 0 && c == 113)    // TEST-NET-3
        || a >= 224) // multicast, reserved, broadcast
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // Only global unicast, 2000::/3, can be public at all. That alone refuses
    // ::, ::1, ::/96 (IPv4-compatible), ::ffff:0:0/96 (IPv4-mapped),
    // 64:ff9b::/96 (NAT64), 100::/64, fc00::/7 (unique local), fe80::/10
    // (link-local), fec0::/10 and ff00::/8 (multicast).
    if s[0] & 0xe000 != 0x2000 {
        return false;
    }
    !(s[0] == 0x2002                                    // 6to4: embeds IPv4
        || (s[0] == 0x2001 && s[1] == 0)                // Teredo 2001::/32
        || (s[0] == 0x2001 && s[1] == 0x0db8)           // documentation
        || (s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0) // benchmarking
        || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010) // ORCHID 2001:10::/28
        || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0020) // ORCHIDv2 2001:20::/28
        || (s[0] == 0x2001 && s[1] < 0x0200)            // IETF protocol assignments
        || (s[0] == 0x3fff && s[1] < 0x1000)) // documentation 3fff::/20
}

/// Resolves host names for the document fetch and refuses the lookup if any
/// answer is not public.
struct PublicOnlyResolver {
    allow_nonpublic: bool,
}

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let allow = self.allow_nonpublic;
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?
                .take(32)
                .collect();
            if addrs.is_empty() {
                return Err("host did not resolve".into());
            }
            // Every answer must be public: one private A record among
            // several is how a rebinding attacker gets the connector to
            // pick it.
            if !allow && addrs.iter().any(|a| !is_public_ip(a.ip())) {
                return Err("host resolves to a non-public address".into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

// ---------------------------------------------------------------------------
// HTTP fetcher
// ---------------------------------------------------------------------------

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);

/// What makes a fetcher production-safe. Only the unit tests can build the
/// relaxed form: there is no configuration, feature or environment variable
/// that loosens it.
#[derive(Clone, Copy)]
struct Policy {
    allow_nonpublic: bool,
    allow_http: bool,
}

/// Fetches documents over HTTPS with the protections described in the module
/// docs.
pub struct HttpDocumentFetcher {
    client: reqwest::Client,
    policy: Policy,
}

impl HttpDocumentFetcher {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::build(Policy {
            allow_nonpublic: false,
            allow_http: false,
        })
    }

    #[cfg(test)]
    fn permissive_for_tests() -> Self {
        Self::build(Policy {
            allow_nonpublic: true,
            allow_http: true,
        })
        .unwrap()
    }

    fn build(policy: Policy) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // A proxy would open the connection itself, past the resolver.
            .no_proxy()
            .dns_resolver(Arc::new(PublicOnlyResolver {
                allow_nonpublic: policy.allow_nonpublic,
            }))
            .https_only(!policy.allow_http)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            // Every fetch resolves and validates afresh.
            .pool_max_idle_per_host(0)
            .user_agent("surge-cimd/1")
            .build()?;
        Ok(Self { client, policy })
    }
}

fn err(msg: impl Into<String>) -> FetchError {
    FetchError(msg.into())
}

#[async_trait]
impl CimdDocumentFetcher for HttpDocumentFetcher {
    async fn fetch(&self, url: &url::Url) -> Result<FetchedDocument, FetchError> {
        if !self.policy.allow_nonpublic {
            // An IP literal never reaches the resolver, so it is refused
            // here as well as by the client ID rules.
            if validate_cimd_client_id(url.as_str()).is_err() {
                return Err(err("not an acceptable document URL"));
            }
        }
        let mut response = self
            .client
            .get(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| err(format!("request failed: {}", describe(&e))))?;

        let status = response.status();
        if status.is_redirection() {
            return Err(err("redirects are not followed"));
        }
        if status != reqwest::StatusCode::OK {
            return Err(err(format!("unexpected status {status}")));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if content_type != "application/json" && !content_type.ends_with("+json") {
            return Err(err("content type is not JSON"));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_CIMD_DOCUMENT_BYTES as u64)
        {
            return Err(err("document is too large"));
        }
        let max_age = response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_max_age);

        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| err(format!("read failed: {}", describe(&e))))?
        {
            if body.len() + chunk.len() > MAX_CIMD_DOCUMENT_BYTES {
                return Err(err("document is too large"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(FetchedDocument { body, max_age })
    }
}

fn describe(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timed out"
    } else if e.is_connect() {
        "could not connect"
    } else if e.is_redirect() {
        "redirected"
    } else {
        "failed"
    }
}

/// `Some(ZERO)` for anything that forbids reuse, `Some(n)` for `max-age=n`,
/// `None` when the header says nothing usable.
fn parse_max_age(header: &str) -> Option<Duration> {
    let mut max_age = None;
    for directive in header.split(',').map(|d| d.trim().to_ascii_lowercase()) {
        if matches!(directive.as_str(), "no-store" | "no-cache" | "private") {
            return Some(Duration::ZERO);
        }
        if let Some(n) = directive.strip_prefix("max-age=")
            && let Ok(n) = n.trim_matches('"').parse::<u64>()
        {
            max_age = Some(Duration::from_secs(n));
        }
    }
    max_age
}

// ---------------------------------------------------------------------------
// Resolver: cache, negative cache, rate limits
// ---------------------------------------------------------------------------

/// Why a client ID could not be resolved to metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CimdError {
    /// The URL or document is not acceptable. Safe to show: it describes the
    /// client's own document.
    Invalid(String),
    /// The document could not be fetched right now.
    Unavailable,
    /// Too many fetches for this host (or in flight overall).
    RateLimited,
}

#[derive(Debug, Clone)]
pub struct CimdLimits {
    /// Freshness when the origin gives none, and the bounds applied when it
    /// does. Short on purpose: a changed redirect URI or a withdrawn
    /// document should take effect quickly.
    pub default_ttl: Duration,
    pub max_ttl: Duration,
    /// How long a failure is remembered, so a broken or hostile document
    /// cannot be used to make this server fetch repeatedly.
    pub negative_ttl: Duration,
    pub outbound_burst: usize,
    pub outbound_window: Duration,
    pub host_burst: usize,
    pub host_window: Duration,
    pub max_cache_entries: usize,
    pub max_concurrent_fetches: usize,
}

impl Default for CimdLimits {
    fn default() -> Self {
        Self {
            default_ttl: Duration::from_secs(300),
            max_ttl: Duration::from_secs(3600),
            negative_ttl: Duration::from_secs(60),
            outbound_burst: 120,
            outbound_window: Duration::from_secs(60),
            host_burst: 10,
            host_window: Duration::from_secs(60),
            max_cache_entries: 1024,
            max_concurrent_fetches: 16,
        }
    }
}

enum Cached {
    Metadata(CimdMetadata),
    Failure(CimdError),
}

struct Entry {
    value: Cached,
    expires: Instant,
}

#[derive(Default)]
struct State {
    cache: HashMap<String, Entry>,
    hosts: HashMap<String, VecDeque<Instant>>,
    outbound: VecDeque<Instant>,
}

pub struct CimdResolver {
    fetcher: Arc<dyn CimdDocumentFetcher>,
    limits: CimdLimits,
    state: Mutex<State>,
    in_flight: Semaphore,
}

impl CimdResolver {
    pub fn new(fetcher: Arc<dyn CimdDocumentFetcher>, limits: CimdLimits) -> Self {
        let in_flight = Semaphore::new(limits.max_concurrent_fetches);
        Self {
            fetcher,
            limits,
            state: Mutex::new(State::default()),
            in_flight,
        }
    }

    /// Resolves `client_id` to validated metadata, from cache when fresh.
    pub async fn resolve(&self, client_id: &str) -> Result<CimdMetadata, CimdError> {
        let url =
            validate_cimd_client_id(client_id).map_err(|m| CimdError::Invalid(m.to_string()))?;
        let host = url.host_str().unwrap_or_default().to_string();
        let _permit = {
            let mut state = self.state.lock().unwrap();
            let now = Instant::now();
            if let Some(entry) = state.cache.get(client_id)
                && entry.expires > now
            {
                return match &entry.value {
                    Cached::Metadata(m) => Ok(m.clone()),
                    Cached::Failure(e) => Err(e.clone()),
                };
            }
            // Rate limit what would reach the network.
            while state
                .outbound
                .front()
                .is_some_and(|t| now.duration_since(*t) >= self.limits.outbound_window)
            {
                state.outbound.pop_front();
            }
            if state.outbound.len() >= self.limits.outbound_burst {
                return Err(CimdError::RateLimited);
            }
            let window = self.limits.host_window;
            let hits = state.hosts.entry(host.clone()).or_default();
            while hits.front().is_some_and(|t| now.duration_since(*t) >= window) {
                hits.pop_front();
            }
            if hits.len() >= self.limits.host_burst {
                return Err(CimdError::RateLimited);
            }
            let permit = self
                .in_flight
                .try_acquire()
                .map_err(|_| CimdError::RateLimited)?;
            hits.push_back(now);
            state.outbound.push_back(now);
            if state.hosts.len() > 4096 {
                state.hosts.retain(|_, h| {
                    h.back().is_some_and(|t| now.duration_since(*t) < window)
                });
            }
            permit
        };

        let outcome = match tokio::time::timeout(
            TOTAL_TIMEOUT + Duration::from_secs(1),
            self.fetcher.fetch(&url),
        )
        .await
        {
            Err(_) => Err(CimdError::Unavailable),
            Ok(Err(e)) => {
                tracing::info!(client_id, error = %e, "cimd document fetch failed");
                Err(CimdError::Unavailable)
            }
            Ok(Ok(doc)) => match parse_cimd_document(client_id, &doc.body) {
                Ok(metadata) => Ok((metadata, doc.max_age)),
                Err(reason) => Err(CimdError::Invalid(reason)),
            },
        };

        let (result, entry) = match outcome {
            Ok((metadata, max_age)) => {
                let ttl = max_age
                    .unwrap_or(self.limits.default_ttl)
                    .min(self.limits.max_ttl);
                let entry = (!ttl.is_zero()).then(|| (Cached::Metadata(metadata.clone()), ttl));
                (Ok(metadata), entry)
            }
            Err(error) => (
                Err(error.clone()),
                Some((Cached::Failure(error), self.limits.negative_ttl)),
            ),
        };
        if let Some((value, ttl)) = entry {
            let mut state = self.state.lock().unwrap();
            self.insert(&mut state, client_id.to_string(), value, ttl);
        }
        result
    }

    fn insert(&self, state: &mut State, key: String, value: Cached, ttl: Duration) {
        let now = Instant::now();
        if state.cache.len() >= self.limits.max_cache_entries && !state.cache.contains_key(&key) {
            state.cache.retain(|_, e| e.expires > now);
            // Still full: drop whichever entry would expire first.
            if state.cache.len() >= self.limits.max_cache_entries
                && let Some(oldest) = state
                    .cache
                    .iter()
                    .min_by_key(|(_, e)| e.expires)
                    .map(|(k, _)| k.clone())
            {
                state.cache.remove(&oldest);
            }
        }
        state.cache.insert(key, Entry { value, expires: now + ttl });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_addresses_are_accepted() {
        for ok in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "172.15.255.255",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "2606:4700:4700::1111",
            "2a00:1450:4001:81b::200e",
        ] {
            assert!(is_public_ip(ip(ok)), "{ok}");
        }
    }

    #[test]
    fn special_purpose_ipv4_is_refused() {
        for bad in [
            "0.0.0.0", "0.1.2.3", "10.0.0.1", "10.255.255.255", "100.64.0.1",
            "100.127.255.255", "127.0.0.1", "127.255.255.254", "169.254.169.254",
            "172.16.0.1", "172.31.255.255", "192.0.0.1", "192.0.2.1", "192.88.99.1",
            "192.168.1.1", "198.18.0.1", "198.19.255.255", "198.51.100.7",
            "203.0.113.9", "224.0.0.1", "239.255.255.255", "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!is_public_ip(ip(bad)), "{bad}");
        }
    }

    #[test]
    fn special_purpose_ipv6_is_refused() {
        for bad in [
            "::",
            "::1",
            // IPv4-mapped and -compatible, carrying private and public v4.
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:8.8.8.8",
            "::127.0.0.1",
            "::8.8.8.8",
            // NAT64, 6to4, Teredo.
            "64:ff9b::7f00:1",
            "64:ff9b::808:808",
            "2002:7f00:1::1",
            "2002:0808:0808::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            // Unique local, link-local, site-local, multicast, discard.
            "fc00::1",
            "fd12:3456:789a::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
            "100::1",
            // Documentation, benchmarking, ORCHID.
            "2001:db8::1",
            "3fff::1",
            "2001:2::1",
            "2001:10::1",
            "2001:20::1",
            "2001:1::1",
        ] {
            assert!(!is_public_ip(ip(bad)), "{bad}");
        }
    }

    #[test]
    fn cache_control_parsing() {
        assert_eq!(parse_max_age("max-age=120"), Some(Duration::from_secs(120)));
        assert_eq!(parse_max_age("public, max-age=30"), Some(Duration::from_secs(30)));
        assert_eq!(parse_max_age("no-store"), Some(Duration::ZERO));
        assert_eq!(parse_max_age("max-age=300, no-cache"), Some(Duration::ZERO));
        assert_eq!(parse_max_age("private, max-age=300"), Some(Duration::ZERO));
        assert_eq!(parse_max_age("max-age=abc"), None);
        assert_eq!(parse_max_age("public"), None);
    }

    // --- resolver, with an injected fetcher --------------------------------

    const ID: &str = "https://app.example/client.json";

    fn body(id: &str) -> Vec<u8> {
        serde_json::json!({
            "client_id": id,
            "client_name": "App",
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "none",
        })
        .to_string()
        .into_bytes()
    }

    type Reply = Box<dyn Fn(&url::Url) -> Result<FetchedDocument, FetchError> + Send + Sync>;

    struct Counting {
        calls: AtomicUsize,
        reply: Reply,
    }

    #[async_trait]
    impl CimdDocumentFetcher for Counting {
        async fn fetch(&self, url: &url::Url) -> Result<FetchedDocument, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            (self.reply)(url)
        }
    }

    fn counting(
        reply: impl Fn(&url::Url) -> Result<FetchedDocument, FetchError> + Send + Sync + 'static,
    ) -> Arc<Counting> {
        Arc::new(Counting {
            calls: AtomicUsize::new(0),
            reply: Box::new(reply),
        })
    }

    fn ok_doc(max_age: Option<Duration>) -> impl Fn(&url::Url) -> Result<FetchedDocument, FetchError> {
        move |u| {
            Ok(FetchedDocument {
                body: body(u.as_str()),
                max_age,
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn documents_are_cached_within_their_freshness() {
        let f = counting(ok_doc(Some(Duration::from_secs(120))));
        let r = CimdResolver::new(f.clone(), CimdLimits::default());
        r.resolve(ID).await.unwrap();
        r.resolve(ID).await.unwrap();
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(121)).await;
        r.resolve(ID).await.unwrap();
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn freshness_is_clamped_and_no_store_is_honoured() {
        let f = counting(ok_doc(Some(Duration::from_secs(10 * 86_400))));
        let r = CimdResolver::new(f.clone(), CimdLimits::default());
        r.resolve(ID).await.unwrap();
        tokio::time::advance(Duration::from_secs(3601)).await;
        r.resolve(ID).await.unwrap();
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);

        let f = counting(ok_doc(Some(Duration::ZERO)));
        let r = CimdResolver::new(f.clone(), CimdLimits::default());
        r.resolve(ID).await.unwrap();
        r.resolve(ID).await.unwrap();
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn failures_are_remembered_briefly() {
        let f = counting(|_| Err(FetchError("boom".into())));
        let r = CimdResolver::new(f.clone(), CimdLimits::default());
        assert_eq!(r.resolve(ID).await, Err(CimdError::Unavailable));
        assert_eq!(r.resolve(ID).await, Err(CimdError::Unavailable));
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(61)).await;
        assert_eq!(r.resolve(ID).await, Err(CimdError::Unavailable));
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);

        // An invalid document is a negative entry too.
        let f = counting(|_| {
            Ok(FetchedDocument {
                body: body("https://app.example/other.json"),
                max_age: None,
            })
        });
        let r = CimdResolver::new(f.clone(), CimdLimits::default());
        assert!(matches!(r.resolve(ID).await, Err(CimdError::Invalid(_))));
        assert!(matches!(r.resolve(ID).await, Err(CimdError::Invalid(_))));
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_urls_never_reach_the_fetcher() {
        let f = counting(ok_doc(None));
        let r = CimdResolver::new(f.clone(), CimdLimits::default());
        for bad in [
            "http://app.example/c.json",
            "https://127.0.0.1/c.json",
            "https://localhost/c.json",
            "https://u@app.example/c.json",
            "https://app.example/c.json#x",
        ] {
            assert!(matches!(r.resolve(bad).await, Err(CimdError::Invalid(_))), "{bad}");
        }
        assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn fetches_are_limited_per_host() {
        let f = counting(ok_doc(Some(Duration::ZERO)));
        let limits = CimdLimits {
            host_burst: 3,
            ..CimdLimits::default()
        };
        let r = CimdResolver::new(f.clone(), limits);
        for i in 0..3 {
            r.resolve(&format!("https://busy.example/c{i}.json")).await.unwrap();
        }
        assert_eq!(
            r.resolve("https://busy.example/c9.json").await,
            Err(CimdError::RateLimited)
        );
        // Another host is unaffected; the window frees the first.
        r.resolve("https://other.example/c.json").await.unwrap();
        tokio::time::advance(Duration::from_secs(61)).await;
        r.resolve("https://busy.example/c9.json").await.unwrap();
        assert_eq!(f.calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn outbound_budget_is_shared_across_hosts_and_replenishes() {
        let f = counting(ok_doc(None));
        let limits = CimdLimits {
            outbound_burst: 2,
            host_burst: 1,
            ..CimdLimits::default()
        };
        let window = limits.outbound_window;
        let r = CimdResolver::new(f.clone(), limits);
        r.resolve(ID).await.unwrap();
        r.resolve("https://other.example/client.json")
            .await
            .unwrap();
        let next = "https://third.example/client.json";
        assert_eq!(r.resolve(next).await, Err(CimdError::RateLimited));
        r.resolve(ID).await.unwrap();
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);
        tokio::time::advance(window).await;
        r.resolve(next).await.unwrap();
        assert_eq!(f.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn the_cache_is_bounded() {
        let f = counting(ok_doc(None));
        let limits = CimdLimits {
            max_cache_entries: 4,
            host_burst: 1000,
            ..CimdLimits::default()
        };
        let r = CimdResolver::new(f, limits);
        for i in 0..20 {
            r.resolve(&format!("https://h{i}.example/c.json")).await.unwrap();
        }
        assert!(r.state.lock().unwrap().cache.len() <= 4);
    }

    // --- the HTTP fetcher against a local server ---------------------------
    //
    // Plain HTTP on loopback, through the test-only permissive policy. The
    // production policy cannot be built this way, which the address-policy
    // tests above and the client ID tests in the engine cover.

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn serve(response: Vec<u8>) -> url::Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let response = response.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(&response).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        url::Url::parse(&format!("http://localhost:{port}/client.json")).unwrap()
    }

    fn http(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status}\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    #[tokio::test]
    async fn the_http_fetcher_returns_a_json_document() {
        let url = serve(http(
            "200 OK",
            "content-type: application/json; charset=utf-8\r\ncache-control: max-age=90\r\n",
            b"{\"a\":1}",
        ))
        .await;
        let doc = HttpDocumentFetcher::permissive_for_tests().fetch(&url).await.unwrap();
        assert_eq!(doc.body, b"{\"a\":1}");
        assert_eq!(doc.max_age, Some(Duration::from_secs(90)));
    }

    #[tokio::test]
    async fn the_http_fetcher_refuses_redirects_errors_and_non_json() {
        let fetcher = HttpDocumentFetcher::permissive_for_tests();
        for (resp, why) in [
            (
                http("302 Found", "location: http://127.0.0.1:1/x\r\n", b""),
                "redirect",
            ),
            (http("404 Not Found", "content-type: application/json\r\n", b"{}"), "404"),
            (http("200 OK", "content-type: text/html\r\n", b"{}"), "html"),
            (http("200 OK", "", b"{}"), "no content type"),
        ] {
            let url = serve(resp).await;
            assert!(fetcher.fetch(&url).await.is_err(), "{why}");
        }
    }

    #[tokio::test]
    async fn the_http_fetcher_bounds_the_body() {
        let fetcher = HttpDocumentFetcher::permissive_for_tests();
        let big = vec![b' '; MAX_CIMD_DOCUMENT_BYTES + 1];
        // Declared length too big.
        let url = serve(http("200 OK", "content-type: application/json\r\n", &big)).await;
        assert!(fetcher.fetch(&url).await.is_err());
        // Undeclared length (read until close), streamed past the cap.
        let mut raw = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n".to_vec();
        raw.extend_from_slice(&big);
        let url = serve(raw).await;
        assert!(fetcher.fetch(&url).await.is_err());
        // Exactly at the cap is fine.
        let ok = vec![b' '; MAX_CIMD_DOCUMENT_BYTES];
        let url = serve(http("200 OK", "content-type: application/json\r\n", &ok)).await;
        assert_eq!(fetcher.fetch(&url).await.unwrap().body.len(), MAX_CIMD_DOCUMENT_BYTES);
    }

    #[tokio::test]
    async fn the_production_fetcher_refuses_local_and_literal_targets() {
        let fetcher = HttpDocumentFetcher::new().unwrap();
        let url = serve(http("200 OK", "content-type: application/json\r\n", b"{}")).await;
        // Plain http, a local name and an IP literal are all refused before
        // any connection is made.
        assert!(fetcher.fetch(&url).await.is_err());
        let literal = url::Url::parse("https://127.0.0.1/client.json").unwrap();
        assert!(fetcher.fetch(&literal).await.is_err());
    }

    #[tokio::test]
    async fn the_resolver_refuses_names_that_resolve_to_loopback() {
        // `localhost` is allowed by name in the permissive tests but must
        // be refused by the production resolver even if it got that far.
        let resolver = PublicOnlyResolver { allow_nonpublic: false };
        let name: Name = "localhost".parse().unwrap();
        assert!(resolver.resolve(name).await.is_err());
    }
}
