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

/// A registered OAuth client's public identifier. Not a secret — it travels
/// in query strings and is logged — but it is minted here so the accepted
/// prefix set stays in one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientId(String);

impl ClientId {
    pub fn generate() -> Self {
        Self(format!("aeg_cid_{}", random_suffix()))
    }

    pub fn from_raw(raw: &str) -> Option<Self> {
        (raw.starts_with("aeg_cid_") && raw.len() > 8).then(|| Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A confidential client's secret. Hashed at rest exactly like a service
/// token; handed back once at registration and never again.
pub struct ClientSecret(SecretString);

impl ClientSecret {
    pub fn generate() -> Self {
        Self(SecretString::from(format!("aeg_cs_{}", random_suffix())))
    }

    pub fn from_raw(raw: &str) -> Option<Self> {
        (raw.starts_with("aeg_cs_") && raw.len() > 7)
            .then(|| Self(SecretString::from(raw.to_string())))
    }

    pub fn hash(&self) -> Vec<u8> {
        sha256(self.0.expose_secret().as_bytes())
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientSecret(aeg_cs_***)")
    }
}

/// A single-use OAuth authorization code. Lives 60 seconds and is redeemed
/// once; the database, not this type, is what enforces the "once".
pub struct AuthorizationCode(SecretString);

impl AuthorizationCode {
    pub fn generate() -> Self {
        Self(SecretString::from(format!("aeg_ac_{}", random_suffix())))
    }

    pub fn from_raw(raw: &str) -> Option<Self> {
        (raw.starts_with("aeg_ac_") && raw.len() > 7)
            .then(|| Self(SecretString::from(raw.to_string())))
    }

    pub fn hash(&self) -> Vec<u8> {
        sha256(self.0.expose_secret().as_bytes())
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for AuthorizationCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthorizationCode(aeg_ac_***)")
    }
}

/// An OAuth refresh token: opaque (unlike the access token, which is a JWT),
/// hashed at rest, and rotated on every use.
pub struct RefreshToken(SecretString);

impl RefreshToken {
    pub fn generate() -> Self {
        Self(SecretString::from(format!("aeg_rt_{}", random_suffix())))
    }

    pub fn from_raw(raw: &str) -> Option<Self> {
        (raw.starts_with("aeg_rt_") && raw.len() > 7)
            .then(|| Self(SecretString::from(raw.to_string())))
    }

    pub fn hash(&self) -> Vec<u8> {
        sha256(self.0.expose_secret().as_bytes())
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshToken(aeg_rt_***)")
    }
}

fn random_suffix() -> String {
    let bytes: [u8; TOKEN_BYTES] = rand::rng().random();
    let encoded = base62::encode(u128::from_be_bytes(bytes));
    format!("{encoded:0>22}")
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
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

    #[test]
    fn oauth_prefixes_are_distinct_and_checked() {
        assert!(ClientId::generate().as_str().starts_with("aeg_cid_"));
        assert!(ClientSecret::generate().expose_secret().starts_with("aeg_cs_"));
        assert!(AuthorizationCode::generate().expose_secret().starts_with("aeg_ac_"));
        assert!(RefreshToken::generate().expose_secret().starts_with("aeg_rt_"));

        // Prefixes are the accepted-set contract: one kind of credential must
        // never parse as another.
        assert!(RefreshToken::from_raw("aeg_ac_0000000000000000000000").is_none());
        assert!(AuthorizationCode::from_raw("aeg_rt_0000000000000000000000").is_none());
        assert!(ClientId::from_raw("aeg_cs_0000000000000000000000").is_none());
    }
}
