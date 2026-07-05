use async_trait::async_trait;
use surge_engine::types::*;

/// Trusted, programmatic auth surface. These methods are **unthrottled** —
/// they carry no rate limiting, CSRF, or CORS policy of their own. Callers
/// invoking them directly (service-to-service, CLI, tests) are assumed to
/// already be inside a trust boundary.
///
/// Untrusted input (a browser, a public form) must go through
/// `surge::router::browser` instead, which wraps these same methods with a
/// `RateLimiter` before ever calling them.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn verify_session(&self, token: &SessionToken) -> Result<Session, AuthError>;

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

    /// Best-effort background maintenance (session GC, flow expiry, ...).
    /// A provider with no router mounted on it does no background work by
    /// itself; `surge::router::browser`'s `spawn_maintenance()` is what
    /// drives this periodically. Default no-op so providers that have
    /// nothing to sweep (e.g. `RemoteProvider`) need not implement it.
    async fn run_maintenance(&self) -> Result<(), AuthError> {
        Ok(())
    }
}
