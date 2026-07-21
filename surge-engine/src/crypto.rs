//! TOTP-secret encryption at rest. Unlike passwords/passphrases, a TOTP seed
//! must be recoverable to verify codes, so it can't be one-way hashed. We
//! encrypt with XChaCha20-Poly1305 under a 32-byte key derived (HKDF-SHA256)
//! from the versioned pepper — domain-separated from password hashing, so no
//! new secret to manage, and key rotation follows pepper rotation. Stored as
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

impl Engine {
    fn totp_enc_key(&self, version: u8) -> Result<Zeroizing<[u8; 32]>, AuthError> {
        let pepper = self.pepper.peppers.get(&version).ok_or_else(|| {
            AuthError::Internal(anyhow::anyhow!("pepper version {version} not found"))
        })?;

        let hk = Hkdf::<Sha256>::new(None, pepper.expose_secret().as_bytes());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(format!("surge-totp-enc-v{version}").as_bytes(), okm.as_mut())
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("totp key derivation: {e}")))?;
        Ok(okm)
    }

    /// Encrypt a TOTP secret with the current pepper version's derived key.
    pub(crate) fn encrypt_secret(&self, plaintext: &[u8]) -> Result<String, AuthError> {
        let version = self.pepper.current_version;
        let key = self.totp_enc_key(version)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("totp encrypt: {e}")))?;

        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        Ok(format!("v{version}${}", hex::encode(blob)))
    }

    /// Decrypt a `v{ver}$hex(nonce||ciphertext)` blob, re-deriving the key for
    /// the version it was written under.
    pub(crate) fn decrypt_secret(&self, stored: &str) -> Result<Vec<u8>, AuthError> {
        let (version_str, hex_blob) = stored
            .split_once('$')
            .ok_or_else(|| AuthError::Internal(anyhow::anyhow!("malformed totp ciphertext")))?;
        let version: u8 = version_str
            .strip_prefix('v')
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| AuthError::Internal(anyhow::anyhow!("malformed totp version")))?;

        let blob = hex::decode(hex_blob)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("totp hex decode: {e}")))?;
        if blob.len() < XNONCE_LEN {
            return Err(AuthError::Internal(anyhow::anyhow!("totp ciphertext too short")));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(XNONCE_LEN);

        let key = self.totp_enc_key(version)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        cipher
            .decrypt(XNonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("totp decrypt: {e}")))
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
