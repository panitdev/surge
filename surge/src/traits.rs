use async_trait::async_trait;
use surge_engine::types::*;

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

    async fn register(&self, req: RegisterRequest) -> Result<Identity, AuthError>;

    async fn authenticate_password(
        &self,
        username: &Username,
        password: &Password,
    ) -> Result<Session, AuthError>;
}
