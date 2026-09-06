//! Authorization codes: 60 seconds, one redemption, enforced by the database.
//!
//! The single-use property is the only thing standing between a code
//! intercepted in a redirect and a token, so it is settled by `UPDATE …
//! WHERE consumed_at IS NULL` inside a transaction that took the row `FOR
//! UPDATE` — not by a read-then-write in application code, which under
//! concurrency is a race with a token on the other side of it.

use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, RunQueryDsl};

use super::{now, AuthorizationGrant};
use crate::models::{NewOauthAuthorizationCode, OauthAuthorizationCodeRow};
use crate::schema::oauth_authorization_code;
use crate::types::*;
use crate::Engine;

/// RFC 6749 says a code SHOULD be short-lived; OAuth 2.1 and the MCP profile
/// treat "short" as seconds, not minutes. A code lives only long enough for a
/// browser redirect and one back-channel exchange.
pub const AUTHORIZATION_CODE_TTL_SECS: i64 = 60;

impl Engine {
    /// Mints a code for an authorization that has already cleared every
    /// check. Returns the plaintext exactly once — only its hash is stored.
    pub async fn mint_authorization_code(
        &self,
        grant: &AuthorizationGrant,
    ) -> Result<AuthorizationCode, AuthError> {
        let code = AuthorizationCode::generate();
        let issued_at = now();
        let expires_at = issued_at + Duration::seconds(AUTHORIZATION_CODE_TTL_SECS);

        let mut conn = self.conn().await?;
        diesel::insert_into(oauth_authorization_code::table)
            .values(&NewOauthAuthorizationCode {
                code_hash: code.hash(),
                client_id: &grant.client_id,
                identity_id: *grant.identity_id.as_uuid(),
                session_id: grant.session_id,
                resource_uri: &grant.resource_uri,
                redirect_uri: &grant.redirect_uri,
                scopes: grant.scopes.clone(),
                code_challenge: &grant.code_challenge,
                code_challenge_method: &grant.code_challenge_method,
                nonce: grant.nonce.as_deref(),
                issued_at,
                expires_at,
            })
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(code)
    }

    /// Redeems a code for the client that presented it. Returns
    /// `InvalidToken` for every failure mode a caller could probe with —
    /// unknown code, wrong client, expired, already redeemed — because
    /// distinguishing them tells an attacker holding a stolen code exactly
    /// what went wrong.
    pub async fn consume_authorization_code(
        &self,
        code: &AuthorizationCode,
        client_id: &str,
    ) -> Result<AuthorizationGrant, AuthError> {
        let code_hash = code.hash();
        let client_id = client_id.to_string();
        let mut conn = self.conn().await?;

        conn.transaction::<_, AuthError, _>(|conn| {
            async move {
                let row: OauthAuthorizationCodeRow = oauth_authorization_code::table
                    .find(&code_hash)
                    .select(OauthAuthorizationCodeRow::as_select())
                    .for_update()
                    .first(conn)
                    .await
                    .map_err(|e| match e {
                        diesel::result::Error::NotFound => AuthError::InvalidToken,
                        other => AuthError::Internal(other.into()),
                    })?;

                if row.client_id != client_id
                    || row.consumed_at.is_some()
                    || row.expires_at < Utc::now()
                {
                    return Err(AuthError::InvalidToken);
                }

                diesel::update(oauth_authorization_code::table.find(&code_hash))
                    .set(oauth_authorization_code::consumed_at.eq(Utc::now()))
                    .execute(conn)
                    .await
                    .map_err(|e| AuthError::Internal(e.into()))?;

                Ok(AuthorizationGrant {
                    client_id: row.client_id,
                    identity_id: IdentityId::from_uuid(row.identity_id),
                    session_id: row.session_id,
                    resource_uri: row.resource_uri,
                    redirect_uri: row.redirect_uri,
                    scopes: row.scopes,
                    code_challenge: row.code_challenge,
                    code_challenge_method: row.code_challenge_method,
                    nonce: row.nonce,
                })
            }
            .scope_boxed()
        })
        .await
    }

    /// Codes are kept a little past expiry so a replay still finds the row
    /// and fails on `consumed_at` rather than on absence; after that they are
    /// noise.
    pub async fn gc_expired_authorization_codes(&self) -> Result<u64, AuthError> {
        let mut conn = self.conn().await?;
        let cutoff = Utc::now() - Duration::hours(1);
        let deleted = diesel::delete(
            oauth_authorization_code::table.filter(oauth_authorization_code::expires_at.lt(cutoff)),
        )
        .execute(&mut conn)
        .await
        .map_err(|e| AuthError::Internal(e.into()))?;
        Ok(deleted as u64)
    }
}

/// Verifies an RFC 7636 `code_verifier` against the stored challenge.
/// `S256` only: `plain` is accepted by neither OAuth 2.1 nor this code path,
/// and an absent challenge never reaches here because authorize rejects it.
pub fn verify_pkce(code_challenge: &str, method: &str, verifier: &str) -> bool {
    use sha2::{Digest, Sha256};

    if method != "S256" {
        return false;
    }
    // RFC 7636 §4.1: 43–128 characters of unreserved ASCII.
    if verifier.len() < 43 || verifier.len() > 128 {
        return false;
    }
    if !verifier
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return false;
    }

    let digest = Sha256::digest(verifier.as_bytes());
    let computed = base64url(&digest);
    constant_time_str_eq(&computed, code_challenge)
}

fn base64url(bytes: &[u8]) -> String {
    // Base64url without padding, per RFC 7636 §A. Hand-rolled to keep the
    // engine free of a base64 dependency it would otherwise use once.
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let indices = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        for (i, idx) in indices.iter().enumerate() {
            if i <= chunk.len() {
                out.push(ALPHABET[*idx as usize] as char);
            }
        }
    }
    out
}

fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 7636 appendix B test vector, which pins both the base64url
    /// encoder and the digest ordering.
    #[test]
    fn pkce_matches_the_rfc_7636_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce(challenge, "S256", verifier));
    }

    #[test]
    fn plain_and_malformed_verifiers_are_refused() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        // `plain` is not merely unsupported here, it is refused: OAuth 2.1
        // removed it and accepting it would undo the whole point of PKCE.
        assert!(!verify_pkce(verifier, "plain", verifier));
        assert!(!verify_pkce(challenge, "S256", "too-short"));
        assert!(!verify_pkce(challenge, "S256", &"a".repeat(129)));
        assert!(!verify_pkce(challenge, "S256", &format!("{verifier}!")));
        assert!(!verify_pkce(challenge, "S256", &"a".repeat(43)));
    }
}
