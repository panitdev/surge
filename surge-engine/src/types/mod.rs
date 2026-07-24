mod error;
mod id;
mod password;
mod token;
mod username;

pub use error::{AuthError, ValidationError};
pub use id::{IdentityId, ServiceId, SessionId};
pub use password::{Password, PasswordError};
pub use token::{FlowId, ResetToken, ServiceToken, SessionToken};
pub use username::{Username, UsernameError};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Identity {
    pub id: IdentityId,
    pub username: Username,
    pub display_name: String,
    pub avatar_url: Option<Url>,
    pub state: IdentityState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Identity {
    pub fn new(
        id: IdentityId,
        username: Username,
        display_name: String,
        avatar_url: Option<Url>,
        state: IdentityState,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            username,
            display_name,
            avatar_url,
            state,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityState {
    Active,
    Disabled,
}

impl std::fmt::Display for IdentityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Disabled => f.write_str("disabled"),
        }
    }
}

impl std::str::FromStr for IdentityState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            other => Err(format!("unknown identity state: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Session {
    pub id: SessionId,
    pub identity: Identity,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub authenticated_via: AuthMethod,
}

impl Session {
    pub fn new(
        id: SessionId,
        identity: Identity,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        authenticated_via: AuthMethod,
    ) -> Self {
        Self {
            id,
            identity,
            issued_at,
            expires_at,
            authenticated_via,
        }
    }
}

/// The sole carrier of a plaintext session token out of the engine/facade.
/// `Session` itself is always token-free.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IssuedSession {
    pub session: Session,
    pub token: SessionToken,
}

impl IssuedSession {
    pub fn new(session: Session, token: SessionToken) -> Self {
        Self { session, token }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilePatch {
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<Option<Url>>,
}

#[derive(Debug)]
pub struct RegisterRequest {
    pub username: Username,
    pub password: Password,
    pub display_name: String,
}
