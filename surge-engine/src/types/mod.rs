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

/// How a session was obtained. Serialized as a bare string into
/// `session.authenticated_via`, so the tag names are wire format — renaming
/// one silently invalidates every stored session that carries it. `External`
/// covers every provider link; the provider name is not recorded here because
/// widening this to an object would break that format for no gain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(from = "String", into = "String")]
pub enum AuthMethod {
    Password,
    External,
    /// A method this build does not know about — a session minted by a newer
    /// server. Kept verbatim so an older client deserializes the session
    /// instead of failing the whole lookup on an unrecognized tag.
    Unknown(String),
}

impl From<String> for AuthMethod {
    fn from(s: String) -> Self {
        match s.as_str() {
            "password" => Self::Password,
            "external" => Self::External,
            _ => Self::Unknown(s),
        }
    }
}

impl From<AuthMethod> for String {
    fn from(method: AuthMethod) -> Self {
        match method {
            AuthMethod::Password => "password".to_string(),
            AuthMethod::External => "external".to_string(),
            AuthMethod::Unknown(s) => s,
        }
    }
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

/// A binding between an external namespace's subject and a Surge identity.
///
/// `provider` and `subject` are opaque: Surge stores and matches them but
/// never parses either, which is what lets one table carry email, OAuth, SAML
/// or anything else. `("email", "alice@example.com")` and
/// `("google", "117...")` are both just links.
///
/// `verified_at` is the authority bit. A link with `None` is a pending claim
/// and cannot authenticate anyone; see [`Engine::authenticate_by_link`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IdentityLink {
    pub provider: String,
    pub subject: String,
    pub identity_id: IdentityId,
    pub verified_at: Option<DateTime<Utc>>,
    pub linked_at: DateTime<Utc>,
}

impl IdentityLink {
    pub fn new(
        provider: String,
        subject: String,
        identity_id: IdentityId,
        verified_at: Option<DateTime<Utc>>,
        linked_at: DateTime<Utc>,
    ) -> Self {
        Self {
            provider,
            subject,
            identity_id,
            verified_at,
            linked_at,
        }
    }

    pub fn is_verified(&self) -> bool {
        self.verified_at.is_some()
    }
}

/// The identity to create when a link resolves to nobody. Used only on the
/// miss: an existing link ignores it entirely, so a caller can pass the same
/// seed on every callback without worrying which branch it takes.
#[derive(Debug, Clone)]
pub struct LinkSeed {
    pub username: Username,
    pub display_name: String,
}

/// The outcome of [`Engine::authenticate_by_link`]. `created` distinguishes a
/// first-time signup from a returning login — the caller usually wants to
/// know (onboarding, welcome mail) and cannot tell from the session alone.
#[derive(Debug)]
#[non_exhaustive]
pub struct LinkAuth {
    pub issued: IssuedSession,
    pub created: bool,
}

impl LinkAuth {
    pub fn new(issued: IssuedSession, created: bool) -> Self {
        Self { issued, created }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_method_round_trips_as_a_bare_string() {
        for (method, tag) in [
            (AuthMethod::Password, "\"password\""),
            (AuthMethod::External, "\"external\""),
        ] {
            let json = serde_json::to_string(&method).unwrap();
            assert_eq!(json, tag, "authenticated_via tags are stored wire format");
            assert_eq!(serde_json::from_str::<AuthMethod>(&json).unwrap(), method);
        }
    }

    /// A session minted by a newer server carries an `authenticated_via` tag
    /// this build has never heard of. It must deserialize rather than fail the
    /// whole session lookup, and must survive a re-serialize unchanged.
    #[test]
    fn an_unknown_auth_method_survives_instead_of_failing_to_deserialize() {
        let parsed: AuthMethod = serde_json::from_str("\"webauthn\"").unwrap();
        assert_eq!(parsed, AuthMethod::Unknown("webauthn".to_string()));
        assert_eq!(serde_json::to_string(&parsed).unwrap(), "\"webauthn\"");
    }

    /// `verified_at` is the authority bit: everything that authenticates a
    /// link keys off it, so a link built without one must never read as usable.
    #[test]
    fn a_link_without_verified_at_is_not_verified() {
        let pending = IdentityLink::new(
            "email".to_string(),
            "alice@example.com".to_string(),
            IdentityId::new(),
            None,
            Utc::now(),
        );
        assert!(!pending.is_verified());

        let confirmed = IdentityLink::new(
            "email".to_string(),
            "alice@example.com".to_string(),
            IdentityId::new(),
            Some(Utc::now()),
            Utc::now(),
        );
        assert!(confirmed.is_verified());
    }
}
