use chrono::Utc;
use diesel::prelude::*;
use diesel_async::{scoped_futures::ScopedFutureExt, AsyncConnection, RunQueryDsl};
use uuid::Uuid;

use crate::models::{IdentityRow, LoginFlowRow};
use crate::schema::{
    browser_session as browser, browser_session_account as member, credential_totp, identity,
    login_flow, session,
};
use crate::*;

/// Evidence verified by the credential-entry handler before finishing this flow.
pub enum VerifiedLogin {
    Password(IdentityId),
    Totp(IdentityId),
    Passphrase(IdentityId),
    Recover(IdentityId, Password),
    Register(RegisterRequest),
}

pub struct CompletedLogin {
    pub issued: IssuedSession,
    pub account_id: Option<Uuid>,
    pub browser_cookie: Option<IssuedBrowserSession>,
}

impl Engine {
    pub async fn finish_login_flow(
        &self,
        id: &str,
        csrf: &str,
        token: Option<&BrowserSessionToken>,
        multi_account: bool,
        verified: VerifiedLogin,
    ) -> Result<CompletedLogin, AuthError> {
        let password_hash = match &verified {
            VerifiedLogin::Register(req) => Some(self.hash_password(&req.password)?),
            VerifiedLogin::Recover(_, password) => Some(self.hash_password(password)?),
            _ => None,
        };
        let ttl = self.session_ttl;
        let mut conn = self.conn().await?;
        conn.transaction(|conn| {
            async move {
                let flow = login_flow::table
                    .find(id)
                    .select(LoginFlowRow::as_select())
                    .for_update()
                    .first(conn)
                    .await
                    .optional()?
                    .ok_or(AuthError::InvalidToken)?;
                if flow.csrf_token != csrf {
                    return Err(AuthError::Forbidden);
                }
                if flow.expires_at <= Utc::now() || flow.attempts >= crate::flow::FLOW_MAX_ATTEMPTS
                {
                    return Err(AuthError::SessionExpired);
                }
                let correct_step = match &verified {
                    VerifiedLogin::Totp(identity) => {
                        flow.state == "awaiting_totp"
                            && flow.identity_id.as_ref() == Some(identity.as_uuid())
                    }
                    _ => flow.state == "created",
                };
                if !correct_step {
                    return Err(AuthError::InvalidToken);
                }
                let mut browser_cookie = None;
                let browser_id = match (flow.login_intent.as_str(), flow.bound_browser_id, token) {
                    ("legacy", None, None) => None,
                    ("sign_in" | "add_account", Some(bound), Some(token)) if multi_account => {
                        let locked = browser::table
                            .find(bound)
                            .filter(browser::token_hash.eq(token.hash()))
                            .filter(browser::revoked_at.is_null())
                            .filter(browser::expires_at.gt(Utc::now()))
                            .select(browser::id)
                            .for_update()
                            .first::<Uuid>(conn)
                            .await
                            .optional()?;
                        Some(locked.ok_or(AuthError::InvalidToken)?)
                    }
                    ("sign_in", None, None) if multi_account => {
                        let new = crate::browser_session::create_browser_session_conn(conn).await?;
                        let id = new.id;
                        browser_cookie = Some(new);
                        Some(id)
                    }
                    _ => return Err(AuthError::InvalidToken),
                };
                let identity = match verified {
                    VerifiedLogin::Register(req) => {
                        crate::identity::insert_identity(conn, &req.username, &req.display_name)
                            .await?
                    }
                    VerifiedLogin::Password(id)
                    | VerifiedLogin::Totp(id)
                    | VerifiedLogin::Passphrase(id)
                    | VerifiedLogin::Recover(id, _) => {
                        let row = identity::table
                            .find(*id.as_uuid())
                            .select(IdentityRow::as_select())
                            .for_update()
                            .first(conn)
                            .await?;
                        let identity = crate::identity::row_to_identity(row)?;
                        if identity.state != IdentityState::Active {
                            return Err(AuthError::IdentityDisabled);
                        }
                        if matches!(verified, VerifiedLogin::Password(_))
                            && credential_totp::table
                                .find(*id.as_uuid())
                                .filter(credential_totp::confirmed_at.is_not_null())
                                .count()
                                .get_result::<i64>(conn)
                                .await?
                                > 0
                        {
                            return Err(AuthError::InvalidCredentials);
                        }
                        identity
                    }
                };
                if let Some(hash) = password_hash {
                    crate::credential::insert_password(conn, identity.id, &hash).await?;
                }
                let identity_id = *identity.id.as_uuid();
                let issued =
                    crate::session::mint_session_conn(conn, identity, AuthMethod::Password, ttl)
                        .await?;
                let mut account_id = None;
                if let Some(browser_id) = browser_id {
                    let existing = member::table
                        .filter(member::browser_session_id.eq(browser_id))
                        .filter(member::identity_id.eq(identity_id))
                        .select((member::account_id, member::session_id))
                        .first::<(Uuid, Uuid)>(conn)
                        .await
                        .optional()?;
                    let session_id = *issued.session.id.as_uuid();
                    account_id = Some(if let Some((account, old_session)) = existing {
                        diesel::update(member::table.find((browser_id, account)))
                            .set(member::session_id.eq(session_id))
                            .execute(conn)
                            .await?;
                        diesel::update(session::table.find(old_session))
                            .set(session::revoked_at.eq(Utc::now()))
                            .execute(conn)
                            .await?;
                        account
                    } else {
                        diesel::insert_into(member::table)
                            .values((
                                member::browser_session_id.eq(browser_id),
                                member::identity_id.eq(identity_id),
                                member::session_id.eq(session_id),
                            ))
                            .returning(member::account_id)
                            .get_result(conn)
                            .await?
                    });
                    if browser_cookie.is_some() {
                        diesel::update(browser::table.find(browser_id))
                            .set(browser::default_account_id.eq(account_id))
                            .execute(conn)
                            .await?;
                    }
                }
                diesel::update(login_flow::table.find(id))
                    .set(login_flow::state.eq("completed"))
                    .execute(conn)
                    .await?;
                Ok(CompletedLogin {
                    issued,
                    account_id,
                    browser_cookie,
                })
            }
            .scope_boxed()
        })
        .await
    }
}
