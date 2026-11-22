use std::time::Duration;

use chrono::Utc;
use diesel::prelude::*;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

use crate::identity::{insert_identity, row_to_identity};
use crate::credential::insert_password;
use crate::models::{IdentityRow, NewSession, SessionRow};
use crate::schema::{identity, session};
use crate::types::*;
use crate::Engine;

impl Engine {
    /// Mint a session for an already-authenticated identity. Generates the
    /// token, stores only its hash, and returns the plaintext once via
    /// `IssuedSession` — the sole carrier of the token out of the engine.
    pub async fn mint_session(
        &self,
        identity_id: IdentityId,
        method: AuthMethod,
    ) -> Result<IssuedSession, AuthError> {
        let identity = self.get_identity(identity_id).await?;
        let mut conn = self.conn().await?;
        mint_session_conn(&mut conn, identity, method, self.session_ttl).await
    }

    /// Atomically create an identity, set its password, and mint a session
    /// for it — one identity + one session, or neither, on a single
    /// connection/transaction. This is `register_and_authenticate`'s
    /// primitive; it never re-authenticates.
    pub async fn create_identity_and_session(
        &self,
        req: RegisterRequest,
    ) -> Result<IssuedSession, AuthError> {
        let hash = self.hash_password(&req.password)?;
        let ttl = self.session_ttl;
        let mut conn = self.conn().await?;

        conn.transaction::<_, AuthError, _>(|conn| {
            async move {
                let identity = insert_identity(conn, &req.username, &req.display_name).await?;
                insert_password(conn, identity.id, &hash).await?;
                mint_session_conn(conn, identity, AuthMethod::Password, ttl).await
            }
            .scope_boxed()
        })
        .await
    }

    pub async fn verify_session(&self, token: &SessionToken) -> Result<Session, AuthError> {
        let mut conn = self.conn().await?;
        verify_session_conn(&mut conn, token).await
    }

    pub async fn revoke_session(&self, token: &SessionToken) -> Result<(), AuthError> {
        let mut conn = self.conn().await?;
        let hash = token.hash();
        let now = Utc::now();

        diesel::update(session::table.filter(session::token_hash.eq(&hash)))
            .set(session::revoked_at.eq(now))
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(())
    }

    /// "Log this person out everywhere" — which includes their OAuth grants.
    ///
    /// The cascade to refresh tokens is not incidental: an OAuth grant is
    /// bound to the identity rather than to the session that authorized it
    /// (internal/oauth-as.md §7), so nothing else here would end it, and a
    /// revoke-everything that left connected apps refreshing would be a lie.
    /// Both writes land in one transaction; the returned count is sessions,
    /// which is what every existing caller reports.
    pub async fn revoke_all_sessions(&self, identity_id: IdentityId) -> Result<u64, AuthError> {
        let mut conn = self.conn().await?;
        let now = Utc::now();
        let identity_uuid = *identity_id.as_uuid();

        conn.transaction::<_, AuthError, _>(|conn| {
            async move {
                let affected = diesel::update(
                    session::table
                        .filter(session::identity_id.eq(identity_uuid))
                        .filter(session::revoked_at.is_null()),
                )
                .set(session::revoked_at.eq(now))
                .execute(conn)
                .await
                .map_err(|e| AuthError::Internal(e.into()))?;

                crate::oauth::revoke_identity_tokens(conn, identity_uuid).await?;

                Ok(affected as u64)
            }
            .scope_boxed()
        })
        .await
    }

    pub async fn gc_expired_sessions(&self) -> Result<u64, AuthError> {
        let mut conn = self.conn().await?;
        let now = Utc::now();

        conn.transaction::<_, AuthError, _>(|conn| {
            async move {
                use crate::schema::{browser_session, browser_session_account as member};

                // All membership mutations take the browser lock first. Restrict
                // the sweep to these IDs even if another row becomes stale later.
                let stale_members = member::table
                    .inner_join(session::table.inner_join(identity::table))
                    .filter(session::expires_at.le(now)
                        .or(session::revoked_at.is_not_null())
                        .or(identity::state.ne("active")))
                    .select(member::browser_session_id);
                let browsers = browser_session::table
                    .filter(browser_session::expires_at.le(now)
                        .or(browser_session::revoked_at.is_not_null())
                        .or(browser_session::id.eq_any(stale_members)))
                    .order(browser_session::id)
                    .select(browser_session::id)
                    .for_update()
                    .skip_locked()
                    .load::<uuid::Uuid>(conn)
                    .await?;

                diesel::delete(
                    browser_session::table
                        .filter(browser_session::id.eq_any(&browsers))
                        .filter(browser_session::expires_at.le(now).or(browser_session::revoked_at.is_not_null())),
                )
                .execute(conn)
                .await?;

                diesel::sql_query(
                    "DELETE FROM surge.browser_session_account a USING surge.session s, surge.identity i
                     WHERE a.browser_session_id = ANY($1) AND a.session_id = s.id
                       AND a.identity_id = i.id
                       AND (i.state <> 'active' OR s.expires_at <= $2 OR s.revoked_at IS NOT NULL)",
                )
                .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(&browsers)
                .bind::<diesel::sql_types::Timestamptz, _>(now)
                .execute(conn)
                .await?;

                let deleted = diesel::delete(
                    session::table
                        .filter(session::expires_at.le(now).or(session::revoked_at.is_not_null()))
                        .filter(session::id.ne_all(member::table.select(member::session_id))),
                )
                .execute(conn)
                .await?;
                Ok(deleted as u64)
            }
            .scope_boxed()
        })
        .await
    }
}

/// Connection-taking core shared by `mint_session` and
/// `create_identity_and_session`. Takes the already-fetched `Identity` so
/// the atomic path doesn't re-query it inside the transaction.
pub(crate) async fn mint_session_conn(
    conn: &mut AsyncPgConnection,
    identity: Identity,
    method: AuthMethod,
    ttl: Duration,
) -> Result<IssuedSession, AuthError> {
    let token = SessionToken::generate();
    let now = Utc::now();
    let expires = now + ttl;
    let sid = SessionId::new();

    let new = NewSession {
        id: *sid.as_uuid(),
        token_hash: token.hash(),
        identity_id: *identity.id.as_uuid(),
        authenticated_via: serde_json::to_value(&method).map_err(|e| AuthError::Internal(e.into()))?,
        issued_at: now,
        expires_at: expires,
    };

    diesel::insert_into(session::table)
        .values(&new)
        .execute(conn)
        .await
        .map_err(|e| AuthError::Internal(e.into()))?;

    Ok(IssuedSession::new(
        Session {
            id: sid,
            identity,
            issued_at: now,
            expires_at: expires,
            authenticated_via: method,
        },
        token,
    ))
}

pub(crate) async fn verify_session_conn(
    conn: &mut AsyncPgConnection,
    token: &SessionToken,
) -> Result<Session, AuthError> {
    let hash = token.hash();
    let now = Utc::now();

    let (session_row, identity_row): (SessionRow, IdentityRow) = session::table
        .inner_join(identity::table)
        .filter(session::token_hash.eq(&hash))
        .filter(session::revoked_at.is_null())
        .filter(session::expires_at.gt(now))
        .select((SessionRow::as_select(), IdentityRow::as_select()))
        .first(conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AuthError::InvalidToken,
            other => AuthError::Internal(other.into()),
        })?;

    session_from_rows(session_row, identity_row)
}

pub(crate) fn session_from_rows(session_row: SessionRow, identity_row: IdentityRow) -> Result<Session, AuthError> {
    let ident = row_to_identity(identity_row)?;

    if ident.state == IdentityState::Disabled {
        return Err(AuthError::IdentityDisabled);
    }

    let method: AuthMethod =
        serde_json::from_value(session_row.authenticated_via.clone())
            .map_err(|e| AuthError::Internal(e.into()))?;

    Ok(Session {
        id: SessionId::from_uuid(session_row.id),
        identity: ident,
        issued_at: session_row.issued_at,
        expires_at: session_row.expires_at,
        authenticated_via: method,
    })
}
