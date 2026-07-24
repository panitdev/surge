use std::sync::RwLock;

use async_trait::async_trait;
use chrono::Utc;
use tracing::warn;

use crate::traits::AuthProvider;
use crate::*;

pub struct TestConfig {
    pub username: String,
    pub display_name: String,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            username: "test-user".into(),
            display_name: "Test User".into(),
        }
    }
}

pub struct TestProvider {
    identity: RwLock<Identity>,
    session_id: SessionId,
    token: SessionToken,
}

impl TestProvider {
    pub fn new(config: TestConfig) -> Result<Self, anyhow::Error> {
        let username = Username::new(&config.username)
            .map_err(|e| anyhow::anyhow!("invalid test username: {e}"))?;

        let identity = Identity::new(
            IdentityId::new(),
            username,
            config.display_name,
            None,
            IdentityState::Active,
        );

        warn!(
            username = %identity.username,
            "TestProvider active -- every request is authenticated as this identity. \
             DO NOT use in production.",
        );

        Ok(Self {
            identity: RwLock::new(identity),
            session_id: SessionId::new(),
            token: SessionToken::generate(),
        })
    }

    fn session(&self) -> Session {
        let identity = self.identity.read().unwrap().clone();
        let now = Utc::now();
        Session::new(
            self.session_id,
            identity,
            now,
            now + chrono::Duration::hours(24),
            AuthMethod::Password,
        )
    }

    fn issued_session(&self) -> IssuedSession {
        IssuedSession::new(self.session(), self.token.clone())
    }
}

#[async_trait]
impl AuthProvider for TestProvider {
    async fn verify_session(&self, _token: &SessionToken) -> Result<Session, AuthError> {
        Ok(self.session())
    }

    async fn revoke_session(&self, _token: &SessionToken) -> Result<(), AuthError> {
        Ok(())
    }

    async fn revoke_all_sessions(&self, _id: IdentityId) -> Result<u64, AuthError> {
        Ok(0)
    }

    async fn identity(&self, _id: IdentityId) -> Result<Identity, AuthError> {
        Ok(self.identity.read().unwrap().clone())
    }

    async fn identity_by_username(&self, _username: &Username) -> Result<Identity, AuthError> {
        Ok(self.identity.read().unwrap().clone())
    }

    async fn update_profile(
        &self,
        _id: IdentityId,
        patch: ProfilePatch,
    ) -> Result<Identity, AuthError> {
        let mut identity = self.identity.write().unwrap();
        if let Some(name) = patch.display_name {
            identity.display_name = name;
        }
        if let Some(url) = patch.avatar_url {
            identity.avatar_url = url;
        }
        identity.updated_at = Utc::now();
        Ok(identity.clone())
    }

    async fn register(&self, _req: RegisterRequest) -> Result<Identity, AuthError> {
        Ok(self.identity.read().unwrap().clone())
    }

    async fn register_and_authenticate(
        &self,
        _req: RegisterRequest,
    ) -> Result<IssuedSession, AuthError> {
        Ok(self.issued_session())
    }

    async fn authenticate_password(
        &self,
        _username: &Username,
        _password: &Password,
    ) -> Result<IssuedSession, AuthError> {
        Ok(self.issued_session())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verify_session_always_succeeds() {
        let provider = TestProvider::new(TestConfig::default()).unwrap();
        let token = SessionToken::from_raw("aeg_s_anything_goes_here_1234").unwrap();
        let session = provider.verify_session(&token).await.unwrap();
        assert_eq!(session.identity.username.as_str(), "test-user");
        assert_eq!(session.identity.display_name, "Test User");
    }

    #[tokio::test]
    async fn update_profile_persists() {
        let provider = TestProvider::new(TestConfig::default()).unwrap();
        let id = provider.identity.read().unwrap().id;

        let patch = ProfilePatch {
            display_name: Some("New Name".into()),
            avatar_url: None,
        };
        let updated = provider.update_profile(id, patch).await.unwrap();
        assert_eq!(updated.display_name, "New Name");

        let token = SessionToken::from_raw("aeg_s_anything_goes_here_1234").unwrap();
        let session = provider.verify_session(&token).await.unwrap();
        assert_eq!(session.identity.display_name, "New Name");
    }
}
