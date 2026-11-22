use chrono::Utc;
use diesel::prelude::*;
use diesel_async::{
    scoped_futures::ScopedFutureExt, AsyncConnection, AsyncPgConnection, RunQueryDsl,
};
use uuid::Uuid;

use crate::schema::{
    browser_session as browser, browser_session_account as member, identity, session,
};
use crate::{AuthError, BrowserSessionToken, Engine, SessionId};

async fn lock_browser(
    conn: &mut AsyncPgConnection,
    token: &BrowserSessionToken,
) -> Result<Option<Uuid>, AuthError> {
    Ok(browser::table
        .filter(browser::token_hash.eq(token.hash()))
        .filter(browser::expires_at.gt(Utc::now()))
        .filter(browser::revoked_at.is_null())
        .select(browser::id)
        .for_update()
        .first(conn)
        .await
        .optional()?)
}

impl Engine {
    pub async fn set_default_account(
        &self,
        token: &BrowserSessionToken,
        account: Uuid,
    ) -> Result<(), AuthError> {
        self.conn()
            .await?
            .transaction(|conn| {
                async move {
                    let id = lock_browser(conn, token)
                        .await?
                        .ok_or(AuthError::InvalidToken)?;
                    let live = member::table
                        .find((id, account))
                        .inner_join(session::table.inner_join(identity::table))
                        .filter(session::expires_at.gt(Utc::now()))
                        .filter(session::revoked_at.is_null())
                        .filter(identity::state.eq("active"))
                        .select(member::account_id)
                        .for_share()
                        .first::<Uuid>(conn)
                        .await
                        .optional()?;
                    live.ok_or(AuthError::NotFound)?;
                    diesel::update(browser::table.find(id))
                        .set(browser::default_account_id.eq(account))
                        .execute(conn)
                        .await?;
                    Ok(())
                }
                .scope_boxed()
            })
            .await
    }

    /// A selected logout is conditional on the exact session resolved for the request.
    pub async fn remove_browser_account(
        &self,
        token: &BrowserSessionToken,
        account: Uuid,
        expected: Option<SessionId>,
    ) -> Result<(), AuthError> {
        self.conn()
            .await?
            .transaction(|conn| {
                async move {
                    let id = lock_browser(conn, token)
                        .await?
                        .ok_or(AuthError::InvalidToken)?;
                    let membership = member::table.find((id, account));
                    let current = membership
                        .select(member::session_id)
                        .first::<Uuid>(conn)
                        .await
                        .optional()?;
                    if let Some(expected) = expected {
                        if current.as_ref() != Some(expected.as_uuid()) {
                            return Err(AuthError::InvalidToken);
                        }
                    }
                    if let Some(session_id) = current {
                        diesel::update(
                            session::table
                                .find(session_id)
                                .filter(session::revoked_at.is_null()),
                        )
                        .set(session::revoked_at.eq(Utc::now()))
                        .execute(conn)
                        .await?;
                        diesel::delete(membership).execute(conn).await?;
                    }
                    Ok(())
                }
                .scope_boxed()
            })
            .await
    }

    /// Adoption rotates this hash under the session row lock. PostgreSQL rechecks
    /// the predicate after waiting, so only one of logout and adoption can win.
    pub async fn logout_legacy_browser(&self, token: &crate::SessionToken) -> Result<(), AuthError> {
        let affected = diesel::update(session::table.filter(session::token_hash.eq(token.hash())))
            .set(session::revoked_at.eq(Utc::now()))
            .execute(&mut self.conn().await?)
            .await?;
        if affected == 0 {
            return Err(AuthError::InvalidToken);
        }
        Ok(())
    }

    pub async fn logout_browser(&self, token: &BrowserSessionToken) -> Result<(), AuthError> {
        self.conn()
            .await?
            .transaction(|conn| {
                async move {
                    if let Some(id) = lock_browser(conn, token).await? {
                        let members = member::table.filter(member::browser_session_id.eq(id));
                        let now = Utc::now();
                        diesel::update(
                            session::table
                                .filter(session::id.eq_any(members.select(member::session_id)))
                                .filter(session::revoked_at.is_null()),
                        )
                        .set(session::revoked_at.eq(now))
                        .execute(conn)
                        .await?;
                        diesel::delete(members).execute(conn).await?;
                        diesel::update(browser::table.find(id))
                            .set(browser::revoked_at.eq(now))
                            .execute(conn)
                            .await?;
                    }
                    Ok(())
                }
                .scope_boxed()
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthMethod, EngineConfig, Password, PepperConfig, RegisterRequest, Username, VerifiedLogin,
    };

    fn registration() -> VerifiedLogin {
        VerifiedLogin::Register(RegisterRequest {
            username: Username::new(&Uuid::now_v7().simple().to_string()).unwrap(),
            password: Password::new("account mutation test password".to_owned().into()).unwrap(),
            display_name: "Test account".to_owned(),
        })
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL DATABASE_URL"]
    async fn account_mutations_serialize_with_flow_completion() {
        let engine = Engine::new(EngineConfig {
            database_url: std::env::var("DATABASE_URL").unwrap().into(),
            pepper: PepperConfig {
                current_version: 1,
                peppers: [(1, "test-pepper".to_owned().into())].into(),
            },
            session_ttl: std::time::Duration::from_secs(3600),
        })
        .await
        .unwrap();
        engine.run_migrations().await.unwrap();
        let flow = engine
            .create_browser_login_flow(None, false, None, None)
            .await
            .unwrap();
        let work = engine
            .finish_login_flow(
                &flow.id,
                &flow.csrf_token,
                None,
                None,
                true,
                registration(),
                "register",
                None,
            )
            .await
            .unwrap();
        let browser = work.browser_cookie.unwrap();
        let work_id = work.account_id.unwrap();
        let other_device = engine
            .mint_session(work.issued.session.identity.id, AuthMethod::Password)
            .await
            .unwrap();
        let flow = engine
            .create_browser_login_flow(None, true, Some(&browser.token), None)
            .await
            .unwrap();
        let personal = engine
            .finish_login_flow(
                &flow.id,
                &flow.csrf_token,
                Some(&browser.token),
                None,
                true,
                registration(),
                "register",
                None,
            )
            .await
            .unwrap();
        let personal_id = personal.account_id.unwrap();
        assert!(matches!(
            engine
                .set_default_account(&browser.token, Uuid::now_v7())
                .await,
            Err(AuthError::NotFound)
        ));
        engine
            .set_default_account(&browser.token, personal_id)
            .await
            .unwrap();
        let (selected, session) = engine
            .resolve_browser_session(&browser.token, None)
            .await
            .unwrap();
        assert_eq!(selected, personal_id);
        assert!(matches!(
            engine
                .remove_browser_account(&browser.token, personal_id, Some(work.issued.session.id))
                .await,
            Err(AuthError::InvalidToken)
        ));
        engine
            .remove_browser_account(&browser.token, selected, Some(session.id))
            .await
            .unwrap();
        engine
            .remove_browser_account(&browser.token, selected, None)
            .await
            .unwrap();
        assert!(engine.verify_session(&personal.issued.token).await.is_err());
        assert!(matches!(
            engine.resolve_browser_session(&browser.token, None).await,
            Err(AuthError::InvalidToken)
        ));
        assert_eq!(
            engine
                .resolve_browser_session(&browser.token, Some(work_id))
                .await
                .unwrap()
                .1
                .id,
            work.issued.session.id
        );
        let flow = engine
            .create_browser_login_flow(None, true, Some(&browser.token), None)
            .await
            .unwrap();
        let finish = engine.finish_login_flow(
            &flow.id,
            &flow.csrf_token,
            Some(&browser.token),
            None,
            true,
            registration(),
            "register",
            None,
        );
        let (result, retired) = tokio::join!(finish, engine.logout_browser(&browser.token));
        retired.unwrap();
        match result {
            Ok(added) => assert!(engine.verify_session(&added.issued.token).await.is_err()),
            Err(error) => assert!(matches!(error, AuthError::InvalidToken)),
        }
        engine.logout_browser(&browser.token).await.unwrap();
        assert!(engine.verify_session(&work.issued.token).await.is_err());
        assert!(engine
            .resolve_browser_session(&browser.token, Some(work_id))
            .await
            .is_err());
        assert!(engine
            .create_browser_login_flow(None, true, Some(&browser.token), None)
            .await
            .is_err());
        let flow = engine
            .create_browser_login_flow(None, true, None, Some(&other_device.token))
            .await
            .unwrap();
        let adoption = engine.finish_login_flow(
            &flow.id, &flow.csrf_token, None, Some(&other_device.token),
            true, registration(), "register", None,
        );
        let (adopted, logout) = tokio::join!(adoption, engine.logout_legacy_browser(&other_device.token));
        match adopted {
            Ok(_) => assert!(matches!(logout, Err(AuthError::InvalidToken))),
            Err(AuthError::InvalidToken) => logout.unwrap(),
            Err(error) => panic!("unexpected adoption error: {error}"),
        }
        assert!(engine.verify_session(&other_device.token).await.is_err());
    }
}
