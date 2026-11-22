use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

use crate::schema::browser_session;
use crate::{AuthError, BrowserSessionToken, Engine};

/// The plaintext credential is returned only when the browser session is issued.
pub struct IssuedBrowserSession {
    pub id: Uuid,
    pub token: BrowserSessionToken,
    pub expires_at: DateTime<Utc>,
}

impl Engine {
    /// Create an empty browser session with its own bounded lifetime.
    pub async fn create_browser_session(&self) -> Result<IssuedBrowserSession, AuthError> {
        let mut conn = self.conn().await?;
        create_browser_session_conn(&mut conn).await
    }
}

pub(crate) async fn create_browser_session_conn(
    conn: &mut AsyncPgConnection,
) -> Result<IssuedBrowserSession, AuthError> {
    let token = BrowserSessionToken::generate();
    let (id, expires_at) = diesel::insert_into(browser_session::table)
        .values(browser_session::token_hash.eq(token.hash()))
        .returning((browser_session::id, browser_session::expires_at))
        .get_result(conn)
        .await
        .map_err(|error| AuthError::Internal(error.into()))?;
    Ok(IssuedBrowserSession {
        id,
        token,
        expires_at,
    })
}
