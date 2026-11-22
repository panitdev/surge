use chrono::Utc;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl, scoped_futures::ScopedFutureExt};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::models::{IdentityRow, LoginFlowRow};
use crate::schema::{
    browser_session as browser, browser_session_account as member, credential_totp, identity,
    login_flow, session,
};
use crate::*;

pub(crate) fn credential_version(hash: &str) -> Vec<u8> {
    Sha256::digest(hash.as_bytes()).to_vec()
}

pub struct PasswordProof {
    pub(crate) id: IdentityId,
    pub(crate) version: Vec<u8>,
}

pub struct PassphraseProof {
    pub(crate) id: IdentityId,
    pub(crate) version: Vec<u8>,
}

/// Evidence verified by the credential-entry handler before finishing this flow.
pub enum VerifiedLogin {
    Password(PasswordProof),
    Totp(IdentityId, String),
    Passphrase(PassphraseProof),
    Recover(PassphraseProof, Password),
    Register(RegisterRequest),
}

impl VerifiedLogin {
    fn identity_id(&self) -> Option<IdentityId> {
        match self {
            Self::Password(proof) => Some(proof.id),
            Self::Totp(id, _) => Some(*id),
            Self::Passphrase(proof) | Self::Recover(proof, _) => Some(proof.id),
            Self::Register(_) => None,
        }
    }
}

pub struct CompletedLogin {
    pub factor_status: FactorStatus,
    pub adopted_legacy: bool,
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
        legacy: Option<&SessionToken>,
        multi_account: bool,
        verified: VerifiedLogin,
        audit_action: &str,
        audit_detail: Option<serde_json::Value>,
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
                    VerifiedLogin::Totp(identity, _) => {
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
                            .select((
                                browser::id,
                                browser::provisional,
                                browser::expires_at,
                                browser::issued_at,
                            ))
                            .for_update()
                            .first::<(Uuid, bool, chrono::DateTime<Utc>, chrono::DateTime<Utc>)>(
                                conn,
                            )
                            .await
                            .optional()?
                            .ok_or(AuthError::InvalidToken)?;
                        let (id, provisional, expiry, issued_at) = locked;
                        if expiry <= Utc::now() {
                            return Err(AuthError::InvalidToken);
                        }
                        if provisional {
                            let token = BrowserSessionToken::generate();
                            let expires_at = issued_at + chrono::Duration::hours(720);
                            diesel::update(browser::table.find(id))
                                .set((
                                    browser::token_hash.eq(token.hash()),
                                    browser::expires_at.eq(expires_at),
                                    browser::provisional.eq(false),
                                ))
                                .execute(conn)
                                .await?;
                            browser_cookie = Some(IssuedBrowserSession {
                                id,
                                token,
                                expires_at,
                            });
                        }
                        Some(id)
                    }
                    ("add_account", None, None) if multi_account => {
                        let bound = flow.bound_legacy_id.ok_or(AuthError::InvalidToken)?;
                        let token = legacy.ok_or(AuthError::InvalidToken)?;
                        // Cross-adoptions can name the same two identities in reverse.
                        // Lock both in UUID order before rechecking the bound session.
                        let target = verified.identity_id().map(|id| *id.as_uuid());
                        identity::table
                            .filter(
                                identity::id
                                    .eq_any(session::table.find(bound).select(session::identity_id))
                                    .or(identity::id.nullable().eq(target)),
                            )
                            .order(identity::id.asc())
                            .select(identity::id)
                            .for_update()
                            .load::<Uuid>(conn)
                            .await?;
                        let owner = session::table
                            .inner_join(identity::table)
                            .filter(session::id.eq(bound))
                            .filter(session::token_hash.eq(token.hash()))
                            .filter(session::revoked_at.is_null())
                            .filter(session::expires_at.gt(Utc::now()))
                            .filter(identity::state.eq("active"))
                            .select(session::identity_id)
                            .for_update()
                            .first::<Uuid>(conn)
                            .await
                            .optional()?
                            .ok_or(AuthError::InvalidToken)?;
                        let new = crate::browser_session::create_browser_session_conn(conn).await?;
                        let account = diesel::insert_into(member::table)
                            .values((
                                member::browser_session_id.eq(new.id),
                                member::identity_id.eq(owner),
                                member::session_id.eq(bound),
                            ))
                            .returning(member::account_id)
                            .get_result::<Uuid>(conn)
                            .await?;
                        diesel::update(browser::table.find(new.id))
                            .set(browser::default_account_id.eq(account))
                            .execute(conn)
                            .await?;
                        diesel::update(session::table.find(bound))
                            .set(session::token_hash.eq(SessionToken::generate().hash()))
                            .execute(conn)
                            .await?;
                        let id = new.id;
                        browser_cookie = Some(new);
                        Some(id)
                    }
                    ("sign_in", None, None) if multi_account => {
                        let new = crate::browser_session::create_browser_session_conn(conn).await?;
                        let id = new.id;
                        browser_cookie = Some(new);
                        Some(id)
                    }
                    _ => return Err(AuthError::InvalidToken),
                };
                let identity = match &verified {
                    VerifiedLogin::Register(req) => {
                        crate::identity::insert_identity(conn, &req.username, &req.display_name)
                            .await?
                    }
                    _ => {
                        let id = verified
                            .identity_id()
                            .ok_or(AuthError::InvalidCredentials)?;
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
                        use crate::schema::{
                            credential_passphrase as phrase, credential_password as pw,
                        };
                        let (hash, version) = match &verified {
                            VerifiedLogin::Password(_) | VerifiedLogin::Totp(_, _) => {
                                let hash = pw::table
                                    .find(*id.as_uuid())
                                    .select(pw::hash)
                                    .for_share()
                                    .first::<String>(conn)
                                    .await
                                    .optional()?;
                                let version = match &verified {
                                    VerifiedLogin::Password(proof) => Some(&proof.version),
                                    _ => flow.password_version.as_ref(),
                                };
                                (hash, version)
                            }
                            VerifiedLogin::Passphrase(proof) | VerifiedLogin::Recover(proof, _) => {
                                let hash = phrase::table
                                    .find(*id.as_uuid())
                                    .filter(phrase::confirmed_at.is_not_null())
                                    .select(phrase::hash)
                                    .for_share()
                                    .first::<String>(conn)
                                    .await
                                    .optional()?;
                                (hash, Some(&proof.version))
                            }
                            VerifiedLogin::Register(_) => unreachable!(),
                        };
                        let hash = hash.ok_or(AuthError::InvalidCredentials)?;
                        if Some(&credential_version(&hash)) != version {
                            return Err(AuthError::InvalidCredentials);
                        }
                        if let VerifiedLogin::Totp(_, code) = &verified {
                            self.verify_totp_conn(conn, id, code).await?;
                        }
                        if matches!(verified, VerifiedLogin::Password(_))
                            && credential_totp::table
                                .find(*id.as_uuid())
                                .select(credential_totp::confirmed_at)
                                .for_share()
                                .first::<Option<chrono::DateTime<Utc>>>(conn)
                                .await
                                .optional()?
                                .flatten()
                                .is_some()
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
                        .for_update()
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
                    if browser_cookie.is_some() && flow.bound_legacy_id.is_none() {
                        diesel::update(browser::table.find(browser_id))
                            .set(browser::default_account_id.eq(account_id))
                            .execute(conn)
                            .await?;
                    }
                }
                use crate::schema::oauth_authorization_request as chooser;
                if let Some(browser_id) = browser_id {
                    diesel::update(chooser::table.filter(chooser::login_id.eq(id)))
                        .set((
                            chooser::session_id.eq(*issued.session.id.as_uuid()),
                            chooser::browser_id.eq(browser_id),
                            chooser::legacy_id.eq(None::<Uuid>),
                        ))
                        .execute(conn)
                        .await?;
                }
                diesel::update(login_flow::table.find(id))
                    .set(login_flow::state.eq("completed"))
                    .execute(conn)
                    .await?;
                let factor_status =
                    crate::factor::factor_status_conn(conn, issued.session.identity.id).await?;
                crate::audit::audit_conn(
                    conn,
                    crate::audit::AuditActor::Identity {
                        id: identity_id.to_string(),
                    },
                    audit_action,
                    serde_json::json!({ "session_id": issued.session.id.to_string() }),
                    audit_detail,
                )
                .await?;
                Ok(CompletedLogin {
                    factor_status,
                    adopted_legacy: flow.bound_legacy_id.is_some(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL DATABASE_URL"]
    async fn changed_credentials_invalidate_pending_login_proofs() {
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
        let username = Username::new(&Uuid::now_v7().simple().to_string()).unwrap();
        let identity = engine.create_identity(&username, "test").await.unwrap();
        let password = Password::new("original test password".to_owned().into()).unwrap();
        engine.set_password(identity.id, &password).await.unwrap();
        let single = engine.create_login_flow(None).await.unwrap();
        let multi = engine.create_login_flow(None).await.unwrap();
        let (_, first) = engine
            .verify_login_password(&username, &password)
            .await
            .unwrap();
        let (_, second) = engine
            .verify_login_password(&username, &password)
            .await
            .unwrap();
        engine
            .set_flow_awaiting_totp(&multi.id, second)
            .await
            .unwrap();
        engine
            .set_password(
                identity.id,
                &Password::new("replacement test password".to_owned().into()).unwrap(),
            )
            .await
            .unwrap();

        async fn assert_stale(
            engine: &Engine,
            flow: crate::flow::FlowInfo,
            attempt: VerifiedLogin,
        ) {
            assert!(matches!(
                engine
                    .finish_login_flow(
                        &flow.id,
                        &flow.csrf_token,
                        None,
                        None,
                        false,
                        attempt,
                        "authenticate",
                        None
                    )
                    .await,
                Err(AuthError::InvalidCredentials)
            ));
        }
        assert_stale(&engine, single, VerifiedLogin::Password(first)).await;

        let enrolled = engine.begin_totp_enrollment(identity.id).await.unwrap();
        let secret = totp_rs::Secret::Encoded(enrolled.secret_base32)
            .to_bytes()
            .unwrap();
        let totp = totp_rs::TOTP::new_unchecked(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            secret,
            None,
            "test".into(),
        );
        let now = Utc::now().timestamp() as u64;
        engine
            .confirm_totp(identity.id, &totp.generate(now))
            .await
            .unwrap();
        let code = totp.generate(now + 30);
        assert_stale(
            &engine,
            multi,
            VerifiedLogin::Totp(identity.id, code.clone()),
        )
        .await;
        engine.verify_totp(identity.id, &code).await.unwrap();

        let phrase = engine
            .begin_passphrase_enrollment(identity.id)
            .await
            .unwrap();
        engine
            .confirm_passphrase(identity.id, &phrase)
            .await
            .unwrap();
        let (_, login) = engine
            .verify_login_passphrase(&username, &phrase)
            .await
            .unwrap();
        let (_, recovery) = engine
            .verify_login_passphrase(&username, &phrase)
            .await
            .unwrap();
        engine.remove_passphrase(identity.id).await.unwrap();
        for attempt in [
            VerifiedLogin::Passphrase(login),
            VerifiedLogin::Recover(recovery, password),
        ] {
            assert_stale(
                &engine,
                engine.create_login_flow(None).await.unwrap(),
                attempt,
            )
            .await;
        }
    }
}
