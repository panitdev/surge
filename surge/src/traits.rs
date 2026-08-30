use async_trait::async_trait;
use surge_engine::types::*;

/// Trusted, programmatic auth surface. These methods are **unthrottled** —
/// they carry no rate limiting, CSRF, or CORS policy of their own. Callers
/// invoking them directly (service-to-service, CLI, tests) are assumed to
/// already be inside a trust boundary.
///
/// Untrusted input (a browser, a public form) must go through the browser
/// router instead (`browser_router()`), which wraps these same methods with
/// rate limiting, CORS, and CSRF before ever calling them.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// `None` means the request carried no usable session token. Each
    /// provider decides whether that authenticates the request.
    async fn verify_session(
        &self,
        token: Option<SessionToken>,
    ) -> Result<Session, AuthError>;

    async fn revoke_session(&self, token: &SessionToken) -> Result<(), AuthError>;

    async fn revoke_all_sessions(&self, id: IdentityId) -> Result<u64, AuthError>;

    async fn identity(&self, id: IdentityId) -> Result<Identity, AuthError>;

    async fn identity_by_username(&self, username: &Username) -> Result<Identity, AuthError>;

    async fn update_profile(
        &self,
        id: IdentityId,
        patch: ProfilePatch,
    ) -> Result<Identity, AuthError>;

    /// Creates an identity only. Mints no session — pair with
    /// `authenticate_password` if you need one, or prefer
    /// `register_and_authenticate` for the atomic path.
    async fn register(&self, req: RegisterRequest) -> Result<Identity, AuthError>;

    /// Atomically creates an identity and mints a session for it: one
    /// identity + one session, or neither. Never re-authenticates.
    async fn register_and_authenticate(&self, req: RegisterRequest)
        -> Result<IssuedSession, AuthError>;

    async fn authenticate_password(
        &self,
        username: &Username,
        password: &Password,
    ) -> Result<IssuedSession, AuthError>;

    /// Sign in through an external provider, creating the identity on first
    /// sight. `seed` is consulted only when the link resolves to nobody, so a
    /// callback can pass the same value every time without knowing whether it
    /// is handling a signup or a returning user.
    ///
    /// Only *verified* links authenticate. Surge cannot check an external
    /// account itself, so reaching this method is the caller's assertion that
    /// it already established proof of control — the OAuth code exchange
    /// completed, or the emailed token came back.
    async fn authenticate_by_link(
        &self,
        provider: &str,
        subject: &str,
        seed: &LinkSeed,
    ) -> Result<LinkAuth, AuthError> {
        let _ = (provider, subject, seed);
        Err(AuthError::Forbidden)
    }

    /// Attach a provider account to an identity that already exists, or
    /// confirm one already attached. Distinct from signing in through a link:
    /// binding a subject to an established account is how an account takeover
    /// would be staged, so it is a separate capability.
    async fn link_identity(
        &self,
        identity_id: IdentityId,
        provider: &str,
        subject: &str,
        verified: bool,
    ) -> Result<IdentityLink, AuthError> {
        let _ = (identity_id, provider, subject, verified);
        Err(AuthError::Forbidden)
    }

    async fn identity_links(&self, identity_id: IdentityId) -> Result<Vec<IdentityLink>, AuthError> {
        let _ = identity_id;
        Err(AuthError::Forbidden)
    }

    async fn unlink_identity(
        &self,
        identity_id: IdentityId,
        provider: &str,
        subject: &str,
    ) -> Result<(), AuthError> {
        let _ = (identity_id, provider, subject);
        Err(AuthError::Forbidden)
    }

    /// Best-effort background maintenance (session GC, flow expiry, ...).
    /// Mounting an embedded browser router drives this periodically; a
    /// provider with no router mounted on it does no background work by
    /// itself unless the caller runs `surge::router::spawn_maintenance`.
    /// Default no-op so providers that have nothing to sweep (e.g.
    /// `RemoteProvider`) need not implement it.
    async fn run_maintenance(&self) -> Result<(), AuthError> {
        Ok(())
    }

    /// Builds the browser-facing router at `/v1`. Each provider builds its
    /// own variant: `EmbeddedProvider` runs handlers locally against its
    /// Engine; `RemoteProvider` reverse-proxies to the remote surge-server.
    /// The consumer mounts the result without caring which mode is active.
    ///
    /// The default is a router that answers every request with 501, so a
    /// provider that has no browser perimeter degrades the way the rest of
    /// this trait does — an error response — rather than taking the
    /// process down mid-request.
    #[cfg(feature = "router")]
    fn browser_router(
        self: std::sync::Arc<Self>,
        config: crate::router::BrowserRouterConfig,
    ) -> axum::Router {
        let _ = config;
        // Scoped under `/v1` rather than left as a bare top-level
        // fallback: merging two routers that both define one panics, and
        // this router gets merged into the application's.
        axum::Router::new().nest(
            "/v1",
            axum::Router::new().fallback(|| async {
                (
                    axum::http::StatusCode::NOT_IMPLEMENTED,
                    axum::Json(serde_json::json!({
                        "error": "not_implemented",
                        "message": "this AuthProvider does not implement browser_router()",
                    })),
                )
            }),
        )
    }
}
