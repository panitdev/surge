//! Recoverable-secret encryption at rest, for the material Surge cannot
//! one-way hash: TOTP seeds (a code must be verifiable against the seed) and
//! OAuth signing keys (a token must be signable). We encrypt with
//! XChaCha20-Poly1305 under a 32-byte key derived (HKDF-SHA256) from the
//! versioned pepper, domain-separated per purpose — so no new secret to
//! manage, and key rotation follows pepper rotation. Stored as
//! `v{pepper_ver}$hex(nonce||ciphertext)`, mirroring the `v{ver}$` scheme
//! already used for password hashes.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use secrecy::ExposeSecret;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::types::AuthError;
use crate::Engine;

const XNONCE_LEN: usize = 24;

/// Domain separator for TOTP seeds. **On-disk format**: every stored TOTP
/// secret was encrypted under a key derived from this exact string, so
/// changing it makes every enrolled authenticator undecryptable.
pub(crate) const TOTP_ENC_DOMAIN: &str = "surge-totp-enc";

/// Domain separator for OAuth signing keys. Distinct from the TOTP one, so a
/// key derived for one purpose can never decrypt material stored for the
/// other even under the same pepper version.
pub(crate) const OAUTH_KEY_ENC_DOMAIN: &str = "surge-oauth-key-enc";

impl Engine {
    /// HKDF-SHA256 over the pepper of the given version, separated by
    /// `domain`. `domain` is on-disk format for everything encrypted under
    /// the result — see the constants above.
    fn derive_enc_key(&self, domain: &str, version: u8) -> Result<Zeroizing<[u8; 32]>, AuthError> {
        let pepper = self.pepper.peppers.get(&version).ok_or_else(|| {
            AuthError::Internal(anyhow::anyhow!("pepper version {version} not found"))
        })?;

        let hk = Hkdf::<Sha256>::new(None, pepper.expose_secret().as_bytes());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(format!("{domain}-v{version}").as_bytes(), okm.as_mut())
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("key derivation: {e}")))?;
        Ok(okm)
    }

    /// Encrypt a TOTP secret with the current pepper version's derived key.
    pub(crate) fn encrypt_secret(&self, plaintext: &[u8]) -> Result<String, AuthError> {
        self.encrypt_in_domain(TOTP_ENC_DOMAIN, plaintext)
    }

    /// Decrypt a TOTP secret written by `encrypt_secret`.
    pub(crate) fn decrypt_secret(&self, stored: &str) -> Result<Vec<u8>, AuthError> {
        self.decrypt_in_domain(TOTP_ENC_DOMAIN, stored)
    }

    pub(crate) fn encrypt_in_domain(
        &self,
        domain: &str,
        plaintext: &[u8],
    ) -> Result<String, AuthError> {
        let version = self.pepper.current_version;
        let key = self.derive_enc_key(domain, version)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("encrypt: {e}")))?;

        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        Ok(format!("v{version}${}", hex::encode(blob)))
    }

    /// Decrypt a `v{ver}$hex(nonce||ciphertext)` blob, re-deriving the key for
    /// the version it was written under.
    pub(crate) fn decrypt_in_domain(
        &self,
        domain: &str,
        stored: &str,
    ) -> Result<Vec<u8>, AuthError> {
        let (version_str, hex_blob) = stored
            .split_once('$')
            .ok_or_else(|| AuthError::Internal(anyhow::anyhow!("malformed ciphertext")))?;
        let version: u8 = version_str
            .strip_prefix('v')
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| AuthError::Internal(anyhow::anyhow!("malformed ciphertext version")))?;

        let blob = hex::decode(hex_blob)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("hex decode: {e}")))?;
        if blob.len() < XNONCE_LEN {
            return Err(AuthError::Internal(anyhow::anyhow!("ciphertext too short")));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(XNONCE_LEN);

        let key = self.derive_enc_key(domain, version)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        cipher
            .decrypt(XNonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("decrypt: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn engine_for_crypto() -> Engine {
        // A pool that is never used (crypto is pure/offline).
        let manager = diesel_async::pooled_connection::AsyncDieselConnectionManager::<
            diesel_async::AsyncPgConnection,
        >::new("postgres://invalid/invalid");
        let pool = diesel_async::pooled_connection::deadpool::Pool::builder(manager)
            .build()
            .unwrap();

        let mut peppers = HashMap::new();
        peppers.insert(1u8, secrecy::SecretString::from("pepper-one".to_string()));
        peppers.insert(2u8, secrecy::SecretString::from("pepper-two".to_string()));

        Engine {
            pool,
            database_url: String::new(),
            pepper: crate::PepperConfig {
                current_version: 2,
                peppers,
            },
            session_ttl: std::time::Duration::from_secs(3600),
        }
    }

    #[test]
    fn round_trip() {
        let engine = engine_for_crypto();
        let secret = b"JBSWY3DPEHPK3PXP";
        let blob = engine.encrypt_secret(secret).unwrap();
        assert!(blob.starts_with("v2$"));
        assert_eq!(engine.decrypt_secret(&blob).unwrap(), secret);
    }

    #[test]
    fn distinct_nonces_produce_distinct_ciphertexts() {
        let engine = engine_for_crypto();
        let a = engine.encrypt_secret(b"same-secret").unwrap();
        let b = engine.encrypt_secret(b"same-secret").unwrap();
        assert_ne!(a, b, "random nonce must make ciphertexts differ");
    }

    /// The domain separator is the only thing keeping a TOTP key and an OAuth
    /// signing key from being the same key under the same pepper version.
    #[test]
    fn domains_do_not_decrypt_each_others_ciphertext() {
        let engine = engine_for_crypto();
        let blob = engine
            .encrypt_in_domain(OAUTH_KEY_ENC_DOMAIN, b"private-key-bytes")
            .unwrap();
        assert_eq!(
            engine.decrypt_in_domain(OAUTH_KEY_ENC_DOMAIN, &blob).unwrap(),
            b"private-key-bytes"
        );
        assert!(engine.decrypt_in_domain(TOTP_ENC_DOMAIN, &blob).is_err());
    }

    /// These strings are on-disk format. Renaming one silently bricks every
    /// secret stored under it, which is exactly the kind of change a test
    /// should make someone justify.
    #[test]
    fn domain_separators_are_pinned() {
        assert_eq!(TOTP_ENC_DOMAIN, "surge-totp-enc");
        assert_eq!(OAUTH_KEY_ENC_DOMAIN, "surge-oauth-key-enc");
    }

    #[test]
    fn tamper_is_rejected() {
        let engine = engine_for_crypto();
        let mut blob = engine.encrypt_secret(b"secret").unwrap();
        // Flip the last hex nibble of the ciphertext/tag.
        let last = blob.pop().unwrap();
        blob.push(if last == 'a' { 'b' } else { 'a' });
        assert!(engine.decrypt_secret(&blob).is_err());
    }
}
