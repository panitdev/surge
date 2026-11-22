use crate::schema::{browser_session as browser, oauth_authorization_request as request};
use crate::{AuthError, BrowserSessionToken, Engine, FlowId, IssuedBrowserSession, SessionToken};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::{
    AsyncConnection, AsyncPgConnection, RunQueryDsl, scoped_futures::ScopedFutureExt,
};
use uuid::Uuid;

pub enum ChooserCredential {
    Browser(BrowserSessionToken),
    Legacy(SessionToken),
}

/// Serialize choices before checking wall-clock expiry. PostgreSQL transaction
/// time can predate a wait on another choice or cleanup.
async fn lock_request(
    conn: &mut AsyncPgConnection,
    id: &str,
    browser: Option<Uuid>,
    legacy: Option<Uuid>,
    after_login: bool,
) -> Result<(), AuthError> {
    let (expiry, login, session) = request::table
        .find(id)
        .filter(request::browser_id.is_not_distinct_from(browser))
        .filter(request::legacy_id.is_not_distinct_from(legacy))
        .select((request::expires_at, request::login_id, request::session_id))
        .for_update()
        .first::<(chrono::DateTime<Utc>, Option<String>, Option<Uuid>)>(conn)
        .await
        .optional()?
        .ok_or(AuthError::InvalidToken)?;
    if expiry <= Utc::now()
        || (after_login && session.is_none())
        || (!after_login && login.is_some())
    {
        return Err(AuthError::InvalidToken);
    }
    Ok(())
}

impl Engine {
    pub async fn create_chooser_browser(&self) -> Result<IssuedBrowserSession, AuthError> {
        let token = BrowserSessionToken::generate();
        let expires_at = Utc::now() + Duration::minutes(10);
        let id = diesel::insert_into(browser::table)
            .values((
                browser::token_hash.eq(token.hash()),
                browser::expires_at.eq(expires_at),
                browser::provisional.eq(true),
            ))
            .returning(browser::id)
            .get_result(&mut self.conn().await?)
            .await?;
        Ok(IssuedBrowserSession {
            id,
            token,
            expires_at,
        })
    }

    async fn chooser_owner(
        &self,
        credential: &ChooserCredential,
    ) -> Result<(Option<Uuid>, Option<Uuid>), AuthError> {
        let token = match credential {
            ChooserCredential::Browser(token) => token,
            ChooserCredential::Legacy(token) => {
                let session = self.verify_session(token).await?;
                return Ok((None, Some(*session.id.as_uuid())));
            }
        };
        browser::table
            .filter(browser::token_hash.eq(token.hash()))
            .filter(browser::revoked_at.is_null())
            .filter(browser::expires_at.gt(Utc::now()))
            .select(browser::id)
            .first(&mut self.conn().await?)
            .await
            .optional()?
            .map(|id| (Some(id), None))
            .ok_or(AuthError::InvalidToken)
    }

    pub async fn save_chooser_request(
        &self,
        credential: &ChooserCredential,
        payload: serde_json::Value,
    ) -> Result<String, AuthError> {
        let (browser, legacy) = self.chooser_owner(credential).await?;
        let id = FlowId::generate().to_string();
        diesel::insert_into(request::table)
            .values((
                request::id.eq(&id),
                request::browser_id.eq(browser),
                request::legacy_id.eq(legacy),
                request::request.eq(payload),
                request::expires_at.eq(Utc::now() + Duration::minutes(10)),
            ))
            .execute(&mut self.conn().await?)
            .await?;
        Ok(id)
    }

    /// Reserve the single choice for a normal hosted login. Only that login can
    /// record the new session in the request as part of its completion transaction.
    pub async fn start_chooser_login(
        &self,
        credential: &ChooserCredential,
        id: &str,
        resume: &str,
    ) -> Result<String, AuthError> {
        let (browser, legacy) = self.chooser_owner(credential).await?;
        let mut conn = self.conn().await?;
        conn.transaction(|conn| {
            async move {
                lock_request(conn, id, browser, legacy, false).await?;
                let flow = Self::insert_login_flow_conn(
                    conn,
                    Some(resume),
                    "add_account",
                    browser,
                    legacy,
                )
                .await?;
                let changed = diesel::update(
                    request::table
                        .find(id)
                        .filter(request::login_id.is_null())
                        .filter(request::expires_at.gt(Utc::now())),
                )
                .set(request::login_id.eq(&flow.id))
                .execute(conn)
                .await?;
                if changed == 0 {
                    return Err(AuthError::InvalidToken);
                }
                Ok(flow.id)
            }
            .scope_boxed()
        })
        .await
    }

    /// Selecting an existing member and resuming a completed login are mutually
    /// exclusive. DELETE RETURNING makes each successful continuation one-use.
    pub async fn take_chooser_request(
        &self,
        credential: &ChooserCredential,
        id: &str,
        after_login: bool,
    ) -> Result<(serde_json::Value, Option<Uuid>), AuthError> {
        let (browser, legacy) = self.chooser_owner(credential).await?;
        let mut conn = self.conn().await?;
        conn.transaction(|conn| {
            async move {
                lock_request(conn, id, browser, legacy, after_login).await?;
                Ok(diesel::delete(request::table.find(id))
                    .returning((request::request, request::session_id))
                    .get_result(conn)
                    .await?)
            }
            .scope_boxed()
        })
        .await
    }

    pub(super) async fn gc_expired_chooser_requests(&self) -> Result<(), AuthError> {
        diesel::delete(request::table.filter(request::expires_at.le(Utc::now())))
            .execute(&mut self.conn().await?)
            .await?;
        Ok(())
    }
}
