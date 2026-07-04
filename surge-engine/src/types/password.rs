use secrecy::{ExposeSecret, SecretString};
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("password must be 8-256 characters")]
    Length,
    #[error("password is too common")]
    Common,
}

const COMMON_PASSWORDS: &[&str] = &[
    "12345678",
    "123456789",
    "1234567890",
    "password",
    "password1",
    "qwerty123",
    "iloveyou",
    "abc12345",
    "admin123",
    "letmein12",
    "welcome1",
    "monkey123",
    "dragon12",
    "master12",
    "qwerty12",
    "login123",
    "princess1",
    "football1",
    "shadow12",
    "sunshine1",
];

pub struct Password(SecretString);

impl Password {
    pub fn new(raw: SecretString) -> Result<Self, PasswordError> {
        let exposed = raw.expose_secret();
        let normalized: String = exposed.nfkc().collect();

        if normalized.len() < 8 || normalized.len() > 256 {
            return Err(PasswordError::Length);
        }

        let lower = normalized.to_lowercase();
        if COMMON_PASSWORDS.iter().any(|&p| p == lower) {
            return Err(PasswordError::Common);
        }

        Ok(Self(SecretString::from(normalized)))
    }

    pub fn expose(&self) -> &str {
        self.expose_secret()
    }

    fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    #[test]
    fn valid_password() {
        assert!(Password::new(pw("correct-horse-battery")).is_ok());
    }

    #[test]
    fn rejects_short() {
        assert!(matches!(
            Password::new(pw("short")),
            Err(PasswordError::Length)
        ));
    }

    #[test]
    fn rejects_common() {
        assert!(matches!(
            Password::new(pw("password")),
            Err(PasswordError::Common)
        ));
    }

    #[test]
    fn normalizes_nfkc() {
        let result = Password::new(pw("pässwörd-long-enough"));
        assert!(result.is_ok());
    }
}
