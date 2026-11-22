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

#[derive(Default, serde::Serialize)]
pub struct BrowserAccountList {
    pub accounts: Vec<BrowserAccount>,
    pub default_account_id: Option<Uuid>,
}

#[derive(serde::Serialize)]
pub struct BrowserAccount {
    pub account_id: Uuid,
    pub identity: BrowserAccountIdentity,
    pub expires_at: DateTime<Utc>,
}

#[derive(serde::Serialize)]
pub struct BrowserAccountIdentity {
    pub id: Uuid,
    pub username: String,
}

impl Engine {
    /// Recover the selector for a legacy consent that predates browser adoption.
    pub async fn account_for_session(&self, token: &BrowserSessionToken, session_id: Uuid) -> Result<Uuid, AuthError> {
        use crate::schema::browser_session_account as member;
        member::table.inner_join(browser_session::table)
            .filter(browser_session::token_hash.eq(token.hash()))
            .filter(member::session_id.eq(session_id))
            .select(member::account_id).first(&mut self.conn().await?).await.optional()?.ok_or(AuthError::InvalidToken)
    }

    pub async fn resolve_browser_session(
        &self,
        token: &BrowserSessionToken,
        selector: Option<Uuid>,
    ) -> Result<(Uuid, crate::Session), AuthError> {
        use crate::models::{IdentityRow, SessionRow};
        use crate::schema::{browser_session_account as member, identity, session};

        let mut conn = self.conn().await?;
        let now = Utc::now();
        let mut query = member::table
            .inner_join(browser_session::table)
            .inner_join(session::table.inner_join(identity::table))
            .filter(browser_session::token_hash.eq(token.hash()))
            .filter(browser_session::revoked_at.is_null())
            .filter(browser_session::expires_at.gt(now))
            .filter(session::revoked_at.is_null())
            .filter(session::expires_at.gt(now))
            .filter(identity::state.eq("active"))
            .select((
                member::account_id,
                SessionRow::as_select(),
                IdentityRow::as_select(),
            ))
            .into_boxed();
        query = match selector {
            Some(id) => query.filter(member::account_id.eq(id)),
            None => query.filter(
                member::account_id
                    .nullable()
                    .eq(browser_session::default_account_id),
            ),
        };
        let (id, session, identity) = query
            .first(&mut conn)
            .await
            .optional()?
            .ok_or(AuthError::InvalidToken)?;
        Ok((id, crate::session::session_from_rows(session, identity)?))
    }

    pub async fn list_browser_accounts(
        &self,
        token: &BrowserSessionToken,
    ) -> Result<BrowserAccountList, AuthError> {
        use crate::schema::{browser_session_account as member, identity, session};

        let mut conn = self.conn().await?;
        let now = Utc::now();
        let rows = member::table
            .inner_join(browser_session::table)
            .inner_join(session::table.inner_join(identity::table))
            .filter(browser_session::token_hash.eq(token.hash()))
            .filter(browser_session::revoked_at.is_null())
            .filter(browser_session::expires_at.gt(now))
            .filter(session::revoked_at.is_null())
            .filter(session::expires_at.gt(now))
            .filter(identity::state.eq("active"))
            .order(member::account_id)
            .select((member::account_id, identity::id, identity::username,
                session::expires_at, browser_session::default_account_id))
            .load::<(Uuid, Uuid, String, DateTime<Utc>, Option<Uuid>)>(&mut conn)
            .await?;
        let mut list = BrowserAccountList::default();
        for (account_id, id, username, expires_at, default_id) in rows {
            if default_id == Some(account_id) {
                list.default_account_id = default_id;
            }
            list.accounts.push(BrowserAccount {
                account_id, identity: BrowserAccountIdentity { id, username }, expires_at,
            });
        }
        Ok(list)
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::browser_session_account as member;
    use crate::{AuthMethod, EngineConfig, PepperConfig, Username};
    use std::time::Duration;

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL DATABASE_URL"]
    async fn resolves_selected_and_default_members_independently() {
        let engine = Engine::new(EngineConfig {
            database_url: std::env::var("DATABASE_URL").unwrap().into(),
            pepper: PepperConfig {
                current_version: 1,
                peppers: [(1, "test-pepper".to_owned().into())].into(),
            },
            session_ttl: Duration::from_secs(3600),
        })
        .await
        .unwrap();
        engine.run_migrations().await.unwrap();
        let browser = engine.create_browser_session().await.unwrap();
        let mut accounts = Vec::new();
        for label in ["work", "personal"] {
            let username = Username::new(&Uuid::now_v7().simple().to_string()).unwrap();
            let identity = engine.create_identity(&username, label).await.unwrap();
            let issued = engine
                .mint_session(identity.id, AuthMethod::Password)
                .await
                .unwrap();
            let account: Uuid = diesel::insert_into(member::table)
                .values((
                    member::browser_session_id.eq(browser.id),
                    member::identity_id.eq(*identity.id.as_uuid()),
                    member::session_id.eq(*issued.session.id.as_uuid()),
                ))
                .returning(member::account_id)
                .get_result(&mut engine.conn().await.unwrap())
                .await
                .unwrap();
            accounts.push((account, issued));
        }
        let [(work, work_session), (personal, personal_session)] = accounts.as_slice() else {
            unreachable!()
        };
        assert!(matches!(
            engine.resolve_browser_session(&browser.token, None).await,
            Err(AuthError::InvalidToken)
        ));
        diesel::update(browser_session::table.find(browser.id))
            .set(browser_session::default_account_id.eq(*personal))
            .execute(&mut engine.conn().await.unwrap())
            .await
            .unwrap();
        assert_eq!(
            engine
                .resolve_browser_session(&browser.token, None)
                .await
                .unwrap()
                .1
                .id,
            personal_session.session.id
        );
        assert_eq!(
            engine
                .resolve_browser_session(&browser.token, Some(*work))
                .await
                .unwrap()
                .1
                .id,
            work_session.session.id
        );
        engine
            .revoke_session(&personal_session.token)
            .await
            .unwrap();
        let list = engine.list_browser_accounts(&browser.token).await.unwrap();
        assert_eq!(list.default_account_id, None);
        assert_eq!(list.accounts.len(), 1);
        assert_eq!(list.accounts[0].account_id, *work);
        assert!(matches!(
            engine.resolve_browser_session(&browser.token, None).await,
            Err(AuthError::InvalidToken)
        ));
        assert_eq!(
            engine
                .resolve_browser_session(&browser.token, Some(*work))
                .await
                .unwrap()
                .0,
            *work
        );
    }
}
