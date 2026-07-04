use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum UsernameError {
    #[error("username must be 3-32 characters")]
    Length,
    #[error("username may only contain lowercase letters, digits, and single hyphens")]
    InvalidChars,
    #[error("username must not start or end with a hyphen")]
    LeadingTrailingHyphen,
    #[error("username must not contain consecutive hyphens")]
    ConsecutiveHyphens,
    #[error("username is reserved")]
    Reserved,
}

const RESERVED: &[&str] = &[
    "abuse",
    "admin",
    "administrator",
    "autoconfig",
    "autodiscover",
    "ftp",
    "hostmaster",
    "info",
    "mailer-daemon",
    "marketing",
    "no-reply",
    "noc",
    "noreply",
    "postmaster",
    "root",
    "sales",
    "security",
    "spam",
    "support",
    "surge",
    "sysadmin",
    "usenet",
    "uucp",
    "webmaster",
    "www",
];

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Username(String);

impl Username {
    pub fn new(raw: &str) -> Result<Self, UsernameError> {
        let folded = raw.to_lowercase();

        if folded.len() < 3 || folded.len() > 32 {
            return Err(UsernameError::Length);
        }

        if folded.starts_with('-') || folded.ends_with('-') {
            return Err(UsernameError::LeadingTrailingHyphen);
        }

        if folded.contains("--") {
            return Err(UsernameError::ConsecutiveHyphens);
        }

        if !folded.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(UsernameError::InvalidChars);
        }

        if RESERVED.binary_search(&folded.as_str()).is_ok() {
            return Err(UsernameError::Reserved);
        }

        Ok(Self(folded))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Username {
    type Error = UsernameError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

impl From<Username> for String {
    fn from(u: Username) -> String {
        u.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Username({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_usernames() {
        assert!(Username::new("alice").is_ok());
        assert!(Username::new("bob-smith").is_ok());
        assert!(Username::new("user123").is_ok());
        assert!(Username::new("a1b").is_ok());
    }

    #[test]
    fn folds_to_lowercase() {
        let u = Username::new("Alice").unwrap();
        assert_eq!(u.as_str(), "alice");
    }

    #[test]
    fn rejects_too_short() {
        assert!(matches!(Username::new("ab"), Err(UsernameError::Length)));
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(33);
        assert!(matches!(Username::new(&long), Err(UsernameError::Length)));
    }

    #[test]
    fn rejects_leading_hyphen() {
        assert!(matches!(
            Username::new("-alice"),
            Err(UsernameError::LeadingTrailingHyphen)
        ));
    }

    #[test]
    fn rejects_trailing_hyphen() {
        assert!(matches!(
            Username::new("alice-"),
            Err(UsernameError::LeadingTrailingHyphen)
        ));
    }

    #[test]
    fn rejects_double_hyphen() {
        assert!(matches!(
            Username::new("al--ice"),
            Err(UsernameError::ConsecutiveHyphens)
        ));
    }

    #[test]
    fn rejects_invalid_chars() {
        assert!(matches!(
            Username::new("al_ice"),
            Err(UsernameError::InvalidChars)
        ));
        assert!(matches!(
            Username::new("al ice"),
            Err(UsernameError::InvalidChars)
        ));
    }

    #[test]
    fn rejects_reserved() {
        assert!(matches!(Username::new("admin"), Err(UsernameError::Reserved)));
        assert!(matches!(Username::new("root"), Err(UsernameError::Reserved)));
        assert!(matches!(
            Username::new("postmaster"),
            Err(UsernameError::Reserved)
        ));
    }
}
