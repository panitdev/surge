use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use secrecy::ExposeSecret;

use crate::models::{CredentialPasswordRow, NewCredentialPassword};
use crate::schema::credential_password;
use crate::types::*;
use crate::Engine;

const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

const DUMMY_HASH_BODY: &str = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$RJfkWz2fZi2V7fUgT0FSQe0DxW/N4mCvIJZ3VJZupYE";

impl Engine {
    pub async fn set_password(
        &self,
        identity_id: IdentityId,
        password: &Password,
    ) -> Result<(), AuthError> {
        let hash = self.hash_password(password)?;
        let mut conn = self.conn().await?;
        let now = Utc::now();

        diesel::insert_into(credential_password::table)
            .values(&NewCredentialPassword {
                identity_id: *identity_id.as_uuid(),
                hash: &hash,
                updated_at: now,
            })
            .on_conflict(credential_password::identity_id)
            .do_update()
            .set((
                credential_password::hash.eq(&hash),
                credential_password::updated_at.eq(now),
            ))
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(())
    }

    pub async fn verify_password(
        &self,
        username: &Username,
        password: &Password,
    ) -> Result<Identity, AuthError> {
        let mut conn = self.conn().await?;

        let result: Result<(crate::models::IdentityRow, CredentialPasswordRow), _> =
            crate::schema::identity::table
                .inner_join(credential_password::table)
                .filter(crate::schema::identity::username.eq(username.as_str()))
                .select((
                    crate::models::IdentityRow::as_select(),
                    CredentialPasswordRow::as_select(),
                ))
                .first(&mut conn)
                .await;

        match result {
            Ok((identity_row, cred_row)) => {
                self.verify_hash(&cred_row.hash, password)?;

                let identity = crate::identity::row_to_identity(identity_row)?;
                if identity.state == IdentityState::Disabled {
                    return Err(AuthError::IdentityDisabled);
                }
                Ok(identity)
            }
            Err(diesel::result::Error::NotFound) => {
                let dummy = format!("v{}${DUMMY_HASH_BODY}", self.pepper.current_version);
                let _ = self.verify_hash(&dummy, password);
                Err(AuthError::InvalidCredentials)
            }
            Err(e) => Err(AuthError::Internal(e.into())),
        }
    }

    fn hash_password(&self, password: &Password) -> Result<String, AuthError> {
        let pepper = self
            .pepper
            .peppers
            .get(&self.pepper.current_version)
            .ok_or_else(|| {
                AuthError::Internal(anyhow::anyhow!(
                    "pepper version {} not found",
                    self.pepper.current_version
                ))
            })?;

        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("argon2 params: {e}")))?;

        let argon2 = Argon2::new_with_secret(
            pepper.expose_secret().as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        )
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("argon2 init: {e}")))?;

        let salt = SaltString::generate(argon2::password_hash::rand_core::OsRng);
        let hash = argon2
            .hash_password(password.expose().as_bytes(), &salt)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("argon2 hash: {e}")))?;

        Ok(format!("v{}${}", self.pepper.current_version, hash))
    }

    fn verify_hash(&self, stored: &str, password: &Password) -> Result<(), AuthError> {
        let (version_str, hash_str) = stored
            .split_once('$')
            .ok_or(AuthError::InvalidCredentials)?;

        let version: u8 = version_str
            .strip_prefix('v')
            .and_then(|v| v.parse().ok())
            .ok_or(AuthError::InvalidCredentials)?;

        let pepper = self
            .pepper
            .peppers
            .get(&version)
            .ok_or_else(|| {
                AuthError::Internal(anyhow::anyhow!("pepper version {version} not found"))
            })?;

        let parsed = PasswordHash::new(hash_str)
            .map_err(|_| AuthError::InvalidCredentials)?;

        let params = Params::try_from(&parsed)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("argon2 params from hash: {e}")))?;

        let argon2 = Argon2::new_with_secret(
            pepper.expose_secret().as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        )
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("argon2 init: {e}")))?;

        argon2
            .verify_password(password.expose().as_bytes(), &parsed)
            .map_err(|_| AuthError::InvalidCredentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_engine_pepper() -> crate::PepperConfig {
        let mut peppers = HashMap::new();
        peppers.insert(1u8, secrecy::SecretString::from("test-pepper".to_string()));
        crate::PepperConfig {
            current_version: 1,
            peppers,
        }
    }

    #[test]
    fn dummy_hash_body_is_valid_phc() {
        let parsed = PasswordHash::new(DUMMY_HASH_BODY).expect("DUMMY_HASH_BODY must be valid PHC");
        Params::try_from(&parsed).expect("DUMMY_HASH_BODY must have valid argon2 params");
    }

    #[test]
    fn dummy_hash_reaches_argon2_verify() {
        let pepper_config = test_engine_pepper();
        let pepper = pepper_config.peppers.get(&1).unwrap();
        let parsed = PasswordHash::new(DUMMY_HASH_BODY).unwrap();
        let params = Params::try_from(&parsed).unwrap();

        let argon2 = Argon2::new_with_secret(
            pepper.expose_secret().as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        )
        .unwrap();

        // Must reach verify_password (and fail — not parse-fail)
        let result = argon2.verify_password(b"any-password", &parsed);
        assert!(result.is_err(), "dummy hash should reject any password");
    }
}
