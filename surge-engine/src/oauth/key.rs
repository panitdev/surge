//! Signing keys for access and ID tokens.
//!
//! ES256, not EdDSA: JWT support for Ed25519 is still uneven across the
//! client ecosystems that will verify these tokens, and P-256 is universally
//! supported. `algorithm` is a column rather than a constant so revisiting
//! that is a data change, not a migration.
//!
//! Private keys are stored encrypted under a key derived from the versioned
//! pepper (`crypto::OAUTH_KEY_ENC_DOMAIN`), so a database leak alone does not
//! forge tokens. The flip side is worth stating plainly: a *pepper* leak now
//! is a token-forgery event, which it was not before this module existed.

use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use rand::Rng;
use zeroize::Zeroizing;

use super::{now, PublicSigningKey, SigningKeyMaterial};
use crate::crypto::OAUTH_KEY_ENC_DOMAIN;
use crate::models::{NewOauthSigningKey, OauthSigningKeyRow};
use crate::schema::oauth_signing_key;
use crate::types::*;
use crate::Engine;

pub const ES256: &str = "ES256";

impl Engine {
    /// The key to sign with, generating one on first use.
    ///
    /// Generation is lazy rather than a startup step: an AS that has never
    /// signed anything has no reason to hold key material, and a deployment
    /// that enables the AS and never receives a request should not have
    /// written a secret to its database.
    pub async fn active_oauth_signing_key(&self) -> Result<SigningKeyMaterial, AuthError> {
        if let Some(row) = self.load_active_signing_key().await? {
            return self.decrypt_signing_key(row);
        }

        // Racing callers both insert; the partial unique index lets exactly
        // one win, and the loser re-reads the winner's key.
        match self.generate_oauth_signing_key(true).await {
            Ok(material) => Ok(material),
            Err(AuthError::Internal(_)) => {
                let row = self
                    .load_active_signing_key()
                    .await?
                    .ok_or_else(|| AuthError::Internal(anyhow::anyhow!("no active signing key")))?;
                self.decrypt_signing_key(row)
            }
            Err(e) => Err(e),
        }
    }

    /// Generates a key, optionally activating it. Public so the CLI can
    /// pre-seed a deployment.
    pub async fn generate_oauth_signing_key(
        &self,
        activate: bool,
    ) -> Result<SigningKeyMaterial, AuthError> {
        let signing_key = generate_p256()?;
        let pkcs8 = signing_key
            .to_pkcs8_der()
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("pkcs8 encode: {e}")))?;
        let pkcs8_der = Zeroizing::new(pkcs8.as_bytes().to_vec());

        let kid = new_kid();
        let public_jwk = public_jwk(&signing_key, &kid);
        let encrypted = self.encrypt_in_domain(OAUTH_KEY_ENC_DOMAIN, &pkcs8_der)?;
        let created_at = now();

        let mut conn = self.conn().await?;
        diesel::insert_into(oauth_signing_key::table)
            .values(&NewOauthSigningKey {
                kid: &kid,
                algorithm: ES256,
                private_key_encrypted: &encrypted,
                public_jwk: public_jwk.clone(),
                created_at,
                activated_at: activate.then_some(created_at),
            })
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(SigningKeyMaterial {
            kid,
            algorithm: ES256.to_string(),
            pkcs8_der,
            public_jwk,
        })
    }

    /// Everything JWKS should publish: the active key plus keys retired but
    /// not yet deleted, so tokens signed just before a rotation still verify.
    pub async fn public_oauth_signing_keys(&self) -> Result<Vec<PublicSigningKey>, AuthError> {
        let mut conn = self.conn().await?;
        let rows: Vec<OauthSigningKeyRow> = oauth_signing_key::table
            .filter(oauth_signing_key::activated_at.is_not_null())
            .order(oauth_signing_key::created_at.desc())
            .select(OauthSigningKeyRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(rows
            .into_iter()
            .map(|row| PublicSigningKey {
                kid: row.kid,
                algorithm: row.algorithm,
                public_jwk: row.public_jwk,
                activated_at: row.activated_at,
                retired_at: row.retired_at,
            })
            .collect())
    }

    /// The rotation step of the maintenance sweep.
    ///
    /// Rotates when the active key is older than `rotate_after`, and deletes
    /// keys retired longer ago than `retire_grace` — which must be at least
    /// two access-token lifetimes, or a token signed a moment before the
    /// rotation stops verifying while it is still valid.
    pub async fn rotate_oauth_signing_keys(
        &self,
        rotate_after: std::time::Duration,
        retire_grace: std::time::Duration,
    ) -> Result<bool, AuthError> {
        let rotate_after = chrono::Duration::from_std(rotate_after)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("rotation interval: {e}")))?;
        let retire_grace = chrono::Duration::from_std(retire_grace)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("retire grace: {e}")))?;

        let mut conn = self.conn().await?;
        diesel::delete(
            oauth_signing_key::table
                .filter(oauth_signing_key::retired_at.lt(Utc::now() - retire_grace)),
        )
        .execute(&mut conn)
        .await
        .map_err(|e| AuthError::Internal(e.into()))?;

        let Some(active) = self.load_active_signing_key().await? else {
            return Ok(false);
        };
        let activated_at = active.activated_at.unwrap_or(active.created_at);
        if Utc::now() - activated_at < rotate_after {
            return Ok(false);
        }

        // Retire first, then activate: the partial unique index permits only
        // one active key, so the order is not a preference.
        let mut conn = self.conn().await?;
        diesel::update(oauth_signing_key::table.find(&active.kid))
            .set(oauth_signing_key::retired_at.eq(Utc::now()))
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        self.generate_oauth_signing_key(true).await?;
        Ok(true)
    }

    async fn load_active_signing_key(&self) -> Result<Option<OauthSigningKeyRow>, AuthError> {
        let mut conn = self.conn().await?;
        oauth_signing_key::table
            .filter(oauth_signing_key::activated_at.is_not_null())
            .filter(oauth_signing_key::retired_at.is_null())
            .select(OauthSigningKeyRow::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AuthError::Internal(e.into()))
    }

    fn decrypt_signing_key(
        &self,
        row: OauthSigningKeyRow,
    ) -> Result<SigningKeyMaterial, AuthError> {
        let der = self.decrypt_in_domain(OAUTH_KEY_ENC_DOMAIN, &row.private_key_encrypted)?;
        Ok(SigningKeyMaterial {
            kid: row.kid,
            algorithm: row.algorithm,
            pkcs8_der: Zeroizing::new(der),
            public_jwk: row.public_jwk,
        })
    }
}

/// Draws 32 bytes and retries the vanishingly rare out-of-range scalar,
/// rather than pulling in a second RNG trait stack to satisfy `random()`.
fn generate_p256() -> Result<SigningKey, AuthError> {
    for _ in 0..8 {
        let bytes: [u8; 32] = rand::rng().random();
        if let Ok(key) = SigningKey::from_bytes(&bytes.into()) {
            return Ok(key);
        }
    }
    Err(AuthError::Internal(anyhow::anyhow!(
        "failed to generate a P-256 key"
    )))
}

fn new_kid() -> String {
    let bytes: [u8; 8] = rand::rng().random();
    hex::encode(bytes)
}

fn public_jwk(key: &SigningKey, kid: &str) -> serde_json::Value {
    let point = key.verifying_key().to_sec1_point(false);
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64url(point.x().expect("uncompressed point has an x coordinate")),
        "y": base64url(point.y().expect("uncompressed point has a y coordinate")),
        "use": "sig",
        "alg": ES256,
        "kid": kid,
    })
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for (i, idx) in [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63]
            .iter()
            .enumerate()
        {
            if i <= chunk.len() {
                out.push(ALPHABET[*idx as usize] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_key_round_trips_through_pkcs8_and_publishes_a_p256_jwk() {
        let key = generate_p256().unwrap();
        let der = key.to_pkcs8_der().unwrap();
        let reloaded = {
            use p256::pkcs8::DecodePrivateKey;
            SigningKey::from_pkcs8_der(der.as_bytes()).unwrap()
        };
        assert_eq!(key.to_bytes(), reloaded.to_bytes());

        let jwk = public_jwk(&key, "test-kid");
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["alg"], "ES256");
        // 32-byte coordinates base64url-encode to 43 characters.
        assert_eq!(jwk["x"].as_str().unwrap().len(), 43);
        assert_eq!(jwk["y"].as_str().unwrap().len(), 43);
    }
}
