//! Refresh tokens: opaque, hashed at rest, rotated on every use, with reuse
//! detection over a `family_id` lineage.
//!
//! **Grants are bound to the identity, not to the browser session that
//! authorized them** (internal/oauth-as.md §7, decided). `session_id` is
//! recorded for audit and carried in the access token's `sid`, but refresh
//! checks identity state rather than session liveness — otherwise every MCP
//! connection would silently break whenever the 72-hour browser session it
//! was born from expired, which is not a security property, just an outage.
//! Explicit revocation still cascades: `revoke_all_sessions` ("log this
//! person out everywhere"), disconnecting the app, and revoking the client
//! all kill the grant.

use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

use super::{now, RefreshGrant};
use crate::models::{NewOauthRefreshToken, OauthRefreshTokenRow};
use crate::schema::{oauth_client, oauth_consent, oauth_refresh_token};
use crate::types::*;
use crate::Engine;

/// The new token from a rotation, plus the grant it carries forward.
#[derive(Debug)]
#[non_exhaustive]
pub struct RotatedRefresh {
    pub token: RefreshToken,
    pub grant: RefreshGrant,
}

impl Engine {
    /// Issues the first refresh token of a new grant (a fresh `family_id`).
    pub async fn issue_refresh_token(
        &self,
        grant: &RefreshGrant,
        ttl: std::time::Duration,
    ) -> Result<RefreshToken, AuthError> {
        let mut conn = self.conn().await?;
        insert_refresh_token(&mut conn, grant, None, ttl).await
    }

    /// Rotates a refresh token: the presented token is consumed and a
    /// successor is minted in the same family, atomically.
    ///
    /// Presenting a token that was already consumed revokes the entire
    /// family. That is the standard response to a stolen refresh token: the
    /// thief and the legitimate client cannot both be holding the newest
    /// token, so a second use of an old one means one of them is replaying,
    /// and the safe move is to end the grant and make the user re-authorize.
    ///
    /// `requested_scopes`, when given, must be a subset of what the grant
    /// carries (RFC 6749 §6: a refresh may narrow but never widen). It is
    /// checked here, inside the transaction and *before* `consumed_at` is
    /// set, so a client that asks for a scope it never held is refused with
    /// its token intact — rejecting it after rotation would burn a valid
    /// token and strand the grant over what is only ever a client-side bug.
    /// The returned grant still carries the full scope set: narrowing shapes
    /// the access token, never the lineage.
    pub async fn rotate_refresh_token(
        &self,
        token: &RefreshToken,
        client_id: &str,
        ttl: std::time::Duration,
        requested_scopes: Option<&[String]>,
    ) -> Result<RotatedRefresh, AuthError> {
        let token_hash = token.hash();
        let client_id = client_id.to_string();
        let owner = client_id.clone();
        let requested_scopes = requested_scopes.map(<[String]>::to_vec);
        let mut conn = self.conn().await?;

        // Reuse is reported as `Ok(Err(family))` rather than as an error,
        // because returning `Err` from a transaction rolls it back — and the
        // one thing that must survive a detected replay is the revocation it
        // triggers.
        let outcome = conn
            .transaction::<_, AuthError, _>(|conn| {
                async move {
                    let row: OauthRefreshTokenRow = oauth_refresh_token::table
                        .find(&token_hash)
                        .select(OauthRefreshTokenRow::as_select())
                        .for_update()
                        .first(conn)
                        .await
                        .map_err(|e| match e {
                            diesel::result::Error::NotFound => AuthError::InvalidToken,
                            other => AuthError::Internal(other.into()),
                        })?;

                    if row.consumed_at.is_some() {
                        // Reuse. Kill the lineage in this same transaction so
                        // a racing replay cannot slip a rotation in between.
                        revoke_family(conn, row.family_id).await?;
                        return Ok(Err(row.family_id));
                    }

                    if row.client_id != client_id
                        || row.revoked_at.is_some()
                        || row.expires_at < Utc::now()
                    {
                        return Err(AuthError::InvalidToken);
                    }

                    // Before the token is spent, not after.
                    if let Some(requested) = &requested_scopes
                        && !requested.iter().all(|s| row.scopes.contains(s))
                    {
                        return Err(AuthError::ScopeNotGranted);
                    }

                    diesel::update(oauth_refresh_token::table.find(&token_hash))
                        .set(oauth_refresh_token::consumed_at.eq(Utc::now()))
                        .execute(conn)
                        .await
                        .map_err(|e| AuthError::Internal(e.into()))?;

                    Ok(Ok(RefreshGrant {
                        client_id: row.client_id,
                        identity_id: IdentityId::from_uuid(row.identity_id),
                        session_id: row.session_id,
                        resource_uri: row.resource_uri,
                        scopes: row.scopes,
                        family_id: row.family_id,
                    }))
                }
                .scope_boxed()
            })
            .await?;

        let grant = match outcome {
            Ok(grant) => grant,
            Err(family_id) => {
                tracing::warn!(
                    %family_id,
                    client_id = %owner,
                    "an already-consumed refresh token was replayed; the grant was revoked"
                );
                return Err(AuthError::InvalidToken);
            }
        };

        let mut conn = self.conn().await?;
        let successor = insert_refresh_token(&mut conn, &grant, Some(token.hash()), ttl).await?;

        Ok(RotatedRefresh {
            token: successor,
            grant,
        })
    }

    /// RFC 7009 revocation. Takes down the whole family, not just the token
    /// presented: a client asking to revoke means the grant is over.
    pub async fn revoke_refresh_token(
        &self,
        token: &RefreshToken,
        client_id: &str,
    ) -> Result<(), AuthError> {
        let mut conn = self.conn().await?;
        let row: Option<OauthRefreshTokenRow> = oauth_refresh_token::table
            .find(token.hash())
            .select(OauthRefreshTokenRow::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AuthError::Internal(e.into()))?;

        // RFC 7009 §2.2: an unknown token is a successful revocation. Saying
        // otherwise turns the endpoint into a token oracle.
        let Some(row) = row else { return Ok(()) };
        if row.client_id != client_id {
            return Ok(());
        }

        revoke_family(&mut conn, row.family_id).await
    }

    /// Cascade for `revoke_all_sessions` — "log this person out everywhere"
    /// would be a lie if their connected apps kept refreshing.
    pub async fn revoke_refresh_tokens_for_identity(
        &self,
        identity_id: IdentityId,
    ) -> Result<u64, AuthError> {
        let mut conn = self.conn().await?;
        revoke_identity_tokens(&mut conn, *identity_id.as_uuid()).await
    }

    /// Is the grant behind an already-issued access token still live?
    ///
    /// This is what makes introspection authoritative for a resource server
    /// that cannot tolerate the access-token TTL as a revocation window. A
    /// grant is live when the identity is active, the client is live, consent
    /// (where consent applies) stands, and at least one refresh token in the
    /// grant has not been revoked — the last being what every cascade above
    /// actually writes.
    pub async fn oauth_grant_is_live(
        &self,
        client_id: &str,
        identity_id: IdentityId,
        resource_uri: &str,
    ) -> Result<bool, AuthError> {
        let identity = match self.get_identity(identity_id).await {
            Ok(identity) => identity,
            Err(AuthError::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };
        if identity.state != IdentityState::Active {
            return Ok(false);
        }

        let mut conn = self.conn().await?;

        let client_live: i64 = oauth_client::table
            .find(client_id)
            .filter(oauth_client::revoked_at.is_null())
            .count()
            .get_result(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;
        if client_live == 0 {
            return Ok(false);
        }

        let tokens_live: i64 = oauth_refresh_token::table
            .filter(oauth_refresh_token::client_id.eq(client_id))
            .filter(oauth_refresh_token::identity_id.eq(*identity_id.as_uuid()))
            .filter(oauth_refresh_token::resource_uri.eq(resource_uri))
            .filter(oauth_refresh_token::revoked_at.is_null())
            .count()
            .get_result(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;
        if tokens_live == 0 {
            return Ok(false);
        }

        // A first-party client has no consent row by design, so its absence
        // is only disqualifying when a row was revoked.
        let consent_revoked: i64 = oauth_consent::table
            .find((client_id, *identity_id.as_uuid(), resource_uri))
            .filter(oauth_consent::revoked_at.is_not_null())
            .count()
            .get_result(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(consent_revoked == 0)
    }

    pub async fn gc_expired_refresh_tokens(&self) -> Result<u64, AuthError> {
        let mut conn = self.conn().await?;
        // Kept a grace period past expiry so a replay of a consumed token
        // still finds its family to revoke.
        let cutoff = Utc::now() - Duration::days(7);
        let deleted = diesel::delete(
            oauth_refresh_token::table.filter(oauth_refresh_token::expires_at.lt(cutoff)),
        )
        .execute(&mut conn)
        .await
        .map_err(|e| AuthError::Internal(e.into()))?;
        Ok(deleted as u64)
    }
}

async fn insert_refresh_token(
    conn: &mut AsyncPgConnection,
    grant: &RefreshGrant,
    parent_hash: Option<Vec<u8>>,
    ttl: std::time::Duration,
) -> Result<RefreshToken, AuthError> {
    let token = RefreshToken::generate();
    let issued_at = now();
    let expires_at = issued_at
        + Duration::from_std(ttl)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("refresh ttl out of range: {e}")))?;

    diesel::insert_into(oauth_refresh_token::table)
        .values(&NewOauthRefreshToken {
            token_hash: token.hash(),
            client_id: &grant.client_id,
            identity_id: *grant.identity_id.as_uuid(),
            session_id: grant.session_id,
            resource_uri: &grant.resource_uri,
            scopes: grant.scopes.clone(),
            family_id: grant.family_id,
            parent_hash,
            issued_at,
            expires_at,
        })
        .execute(conn)
        .await
        .map_err(|e| AuthError::Internal(e.into()))?;

    Ok(token)
}

pub(crate) async fn revoke_family(
    conn: &mut AsyncPgConnection,
    family_id: Uuid,
) -> Result<(), AuthError> {
    diesel::update(
        oauth_refresh_token::table
            .filter(oauth_refresh_token::family_id.eq(family_id))
            .filter(oauth_refresh_token::revoked_at.is_null()),
    )
    .set(oauth_refresh_token::revoked_at.eq(Utc::now()))
    .execute(conn)
    .await
    .map_err(|e| AuthError::Internal(e.into()))?;
    Ok(())
}

pub(crate) async fn revoke_identity_tokens(
    conn: &mut AsyncPgConnection,
    identity_id: Uuid,
) -> Result<u64, AuthError> {
    let affected = diesel::update(
        oauth_refresh_token::table
            .filter(oauth_refresh_token::identity_id.eq(identity_id))
            .filter(oauth_refresh_token::revoked_at.is_null()),
    )
    .set(oauth_refresh_token::revoked_at.eq(Utc::now()))
    .execute(conn)
    .await
    .map_err(|e| AuthError::Internal(e.into()))?;
    Ok(affected as u64)
}
