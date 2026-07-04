use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

const TOKEN_BYTES: usize = 16; // 128 bits

#[derive(Clone)]
pub struct SessionToken(SecretString);

impl SessionToken {
    pub fn generate() -> Self {
        Self::generate_with_prefix("aeg_s_")
    }

    pub fn from_raw(raw: &str) -> Option<Self> {
        if raw.starts_with("aeg_s_") && raw.len() > 6 {
            Some(Self(SecretString::from(raw.to_string())))
        } else {
            None
        }
    }

    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.0.expose_secret().as_bytes());
        hasher.finalize().to_vec()
    }

    pub fn hash_prefix(&self) -> String {
        hex::encode(&self.hash()[..4])
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }

    fn generate_with_prefix(prefix: &str) -> Self {
        let bytes: [u8; TOKEN_BYTES] = rand::rng().random();
        let encoded = base62::encode(u128::from_be_bytes(bytes));
        let padded = format!("{encoded:0>22}");
        Self(SecretString::from(format!("{prefix}{padded}")))
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionToken(aeg_s_***)")
    }
}

pub struct ServiceToken(SecretString);

impl ServiceToken {
    pub fn generate() -> Self {
        let bytes: [u8; TOKEN_BYTES] = rand::rng().random();
        let encoded = base62::encode(u128::from_be_bytes(bytes));
        let padded = format!("{encoded:0>22}");
        Self(SecretString::from(format!("aeg_svc_{padded}")))
    }

    pub fn from_raw(raw: &str) -> Option<Self> {
        if raw.starts_with("aeg_svc_") && raw.len() > 8 {
            Some(Self(SecretString::from(raw.to_string())))
        } else {
            None
        }
    }

    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.0.expose_secret().as_bytes());
        hasher.finalize().to_vec()
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for ServiceToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServiceToken(aeg_svc_***)")
    }
}

pub struct FlowId(String);

impl FlowId {
    pub fn generate() -> Self {
        let bytes: [u8; TOKEN_BYTES] = rand::rng().random();
        let encoded = base62::encode(u128::from_be_bytes(bytes));
        let padded = format!("{encoded:0>22}");
        Self(format!("aeg_f_{padded}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FlowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Debug for FlowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FlowId({})", self.0)
    }
}

pub struct ResetToken(SecretString);

impl ResetToken {
    pub fn generate() -> Self {
        let bytes: [u8; TOKEN_BYTES] = rand::rng().random();
        let encoded = base62::encode(u128::from_be_bytes(bytes));
        let padded = format!("{encoded:0>22}");
        Self(SecretString::from(format!("aeg_r_{padded}")))
    }

    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.0.expose_secret().as_bytes());
        hasher.finalize().to_vec()
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for ResetToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResetToken(aeg_r_***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_token_format() {
        let t = SessionToken::generate();
        let raw = t.expose_secret();
        assert!(raw.starts_with("aeg_s_"));
        assert!(raw.len() >= 28);
    }

    #[test]
    fn session_token_hash_is_stable() {
        let t = SessionToken::from_raw("aeg_s_test1234567890123456").unwrap();
        let h1 = t.hash();
        let h2 = t.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn service_token_format() {
        let t = ServiceToken::generate();
        let raw = t.expose_secret();
        assert!(raw.starts_with("aeg_svc_"));
    }

    #[test]
    fn flow_id_format() {
        let f = FlowId::generate();
        assert!(f.as_str().starts_with("aeg_f_"));
    }

    #[test]
    fn from_raw_rejects_bad_prefix() {
        assert!(SessionToken::from_raw("bad_token").is_none());
        assert!(ServiceToken::from_raw("aeg_s_nope").is_none());
    }
}
