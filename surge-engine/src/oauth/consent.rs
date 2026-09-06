//! Consent records and the consent round-trip.
//!
//! Two halves of the same idea. `oauth_consent` is the durable answer — what
//! this person has approved for this client at this resource — and it is what
//! `GET /v1/account/connections` reads. `oauth_consent_flow` is the pending
//! question, shaped exactly like `login_flow`: a server-side record the auth
//! UI fetches by id, so nothing about the grant travels through the browser
//! where a client could rewrite it.

use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, RunQueryDsl};

use super::client::row_to_client;
use super::{now, ConsentFlow, ConsentGrant, Connection};
use crate::models::{
    NewOauthConsent, NewOauthConsentFlow, OauthClientRow, OauthConsentFlowRow, OauthConsentRow,
};
use crate::schema::{oauth_client, oauth_consent, oauth_consent_flow, oauth_refresh_token};
use crate::types::*;
use crate::Engine;

/// A consent screen is a person reading a sentence and deciding. Ten minutes
/// matches `login_flow`; longer would leave a decidable grant lying around
/// after the user has walked away from it.
const CONSENT_FLOW_TTL_MINUTES: i64 = 10;

impl Engine {
    /// Records approval. Re-approving replaces the scope set rather than
    /// unioning it: the screen the user just read is the whole agreement, so
    /// a later narrower approval must actually narrow.
    pub async fn record_consent(
        &self,
        client_id: &str,
        identity_id: IdentityId,
        resource_uri: &str,
        scopes: Vec<String>,
    ) -> Result<ConsentGrant, AuthError> {
        let granted_at = now();
        let mut conn = self.conn().await?;

        diesel::insert_into(oauth_consent::table)
            .values(&NewOauthConsent {
                client_id,
                identity_id: *identity_id.as_uuid(),
                resource_uri,
                scopes: scopes.clone(),
                granted_at,
            })
            .on_conflict((
                oauth_consent::client_id,
                oauth_consent::identity_id,
                oauth_consent::resource_uri,
            ))
            .do_update()
            .set((
                oauth_consent::scopes.eq(scopes.clone()),
                oauth_consent::granted_at.eq(granted_at),
                oauth_consent::revoked_at.eq(None::<chrono::DateTime<Utc>>),
            ))
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(ConsentGrant {
            client_id: client_id.to_string(),
            identity_id,
            resource_uri: resource_uri.to_string(),
            scopes,
            granted_at,
        })
    }

    /// The live consent for one (client, identity, resource), if any.
    pub async fn find_consent(
        &self,
        client_id: &str,
        identity_id: IdentityId,
        resource_uri: &str,
    ) -> Result<Option<ConsentGrant>, AuthError> {
        let mut conn = self.conn().await?;
        let row: Option<OauthConsentRow> = oauth_consent::table
            .find((client_id, *identity_id.as_uuid(), resource_uri))
            .filter(oauth_consent::revoked_at.is_null())
            .select(OauthConsentRow::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(row.map(|r| ConsentGrant {
            client_id: r.client_id,
            identity_id: IdentityId::from_uuid(r.identity_id),
            resource_uri: r.resource_uri,
            scopes: r.scopes,
            granted_at: r.granted_at,
        }))
    }

    /// "Show me every app connected to my account." Shipping token issuance
    /// without this is not an option — it is the only reason third-party
    /// OAuth is tolerable for the person whose account it is.
    pub async fn list_connections(
        &self,
        identity_id: IdentityId,
    ) -> Result<Vec<Connection>, AuthError> {
        let mut conn = self.conn().await?;
        let rows: Vec<(OauthConsentRow, OauthClientRow)> = oauth_consent::table
            .inner_join(oauth_client::table)
            .filter(oauth_consent::identity_id.eq(*identity_id.as_uuid()))
            .filter(oauth_consent::revoked_at.is_null())
            .filter(oauth_client::revoked_at.is_null())
            .order(oauth_consent::granted_at.desc())
            .select((OauthConsentRow::as_select(), OauthClientRow::as_select()))
            .load(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(rows
            .into_iter()
            .map(|(consent, client_row)| {
                let client = row_to_client(client_row);
                Connection {
                    client_id: client.client_id,
                    client_name: client.client_name,
                    client_uri: client.client_uri,
                    logo_uri: client.logo_uri,
                    registration_source: client.registration_source,
                    resource_uri: consent.resource_uri,
                    scopes: consent.scopes,
                    granted_at: consent.granted_at,
                }
            })
            .collect())
    }

    /// Disconnect an app: revokes every consent this identity gave the client
    /// and every refresh token issued under them, in one transaction. A
    /// disconnect that left the tokens alive would be a lie told in a
    /// settings screen.
    pub async fn revoke_connection(
        &self,
        identity_id: IdentityId,
        client_id: &str,
    ) -> Result<(), AuthError> {
        let mut conn = self.conn().await?;
        let at = now();
        let client_id = client_id.to_string();
        let identity_uuid = *identity_id.as_uuid();

        conn.transaction::<_, AuthError, _>(|conn| {
            async move {
                let affected = diesel::update(
                    oauth_consent::table
                        .filter(oauth_consent::identity_id.eq(identity_uuid))
                        .filter(oauth_consent::client_id.eq(&client_id))
                        .filter(oauth_consent::revoked_at.is_null()),
                )
                .set(oauth_consent::revoked_at.eq(at))
                .execute(conn)
                .await
                .map_err(|e| AuthError::Internal(e.into()))?;

                let tokens = diesel::update(
                    oauth_refresh_token::table
                        .filter(oauth_refresh_token::identity_id.eq(identity_uuid))
                        .filter(oauth_refresh_token::client_id.eq(&client_id))
                        .filter(oauth_refresh_token::revoked_at.is_null()),
                )
                .set(oauth_refresh_token::revoked_at.eq(at))
                .execute(conn)
                .await
                .map_err(|e| AuthError::Internal(e.into()))?;

                // A first-party client has no consent row, so "nothing to
                // revoke" is only true when there were no tokens either.
                if affected == 0 && tokens == 0 {
                    return Err(AuthError::NotFound);
                }
                Ok(())
            }
            .scope_boxed()
        })
        .await
    }

    pub async fn create_consent_flow(&self, flow: ConsentFlowRequest) -> Result<ConsentFlow, AuthError> {
        let id = FlowId::generate();
        let csrf = FlowId::generate();
        let created_at = now();
        let expires_at = created_at + Duration::minutes(CONSENT_FLOW_TTL_MINUTES);

        let mut conn = self.conn().await?;
        diesel::insert_into(oauth_consent_flow::table)
            .values(&NewOauthConsentFlow {
                id: id.as_str(),
                client_id: &flow.client_id,
                identity_id: *flow.identity_id.as_uuid(),
                session_id: flow.session_id,
                resource_uri: &flow.resource_uri,
                scopes: flow.scopes.clone(),
                redirect_uri: &flow.redirect_uri,
                state: flow.state.as_deref(),
                nonce: flow.nonce.as_deref(),
                code_challenge: &flow.code_challenge,
                code_challenge_method: &flow.code_challenge_method,
                csrf_token: csrf.as_str(),
                expires_at,
                created_at,
            })
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(ConsentFlow {
            id: id.as_str().to_string(),
            client_id: flow.client_id,
            identity_id: flow.identity_id,
            session_id: flow.session_id,
            resource_uri: flow.resource_uri,
            scopes: flow.scopes,
            redirect_uri: flow.redirect_uri,
            state: flow.state,
            nonce: flow.nonce,
            code_challenge: flow.code_challenge,
            code_challenge_method: flow.code_challenge_method,
            csrf_token: csrf.as_str().to_string(),
            expires_at,
        })
    }

    pub async fn get_consent_flow(&self, id: &str) -> Result<ConsentFlow, AuthError> {
        let mut conn = self.conn().await?;
        let row: OauthConsentFlowRow = oauth_consent_flow::table
            .find(id)
            .select(OauthConsentFlowRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::NotFound => AuthError::NotFound,
                other => AuthError::Internal(other.into()),
            })?;

        if row.decided_at.is_some() || row.expires_at < Utc::now() {
            return Err(AuthError::SessionExpired);
        }
        Ok(row_to_consent_flow(row))
    }

    /// Marks a consent flow decided and returns it. Single-use, settled in
    /// the database: the approve step mints a code, and a flow that could be
    /// submitted twice is a code-minting oracle.
    pub async fn decide_consent_flow(&self, id: &str) -> Result<ConsentFlow, AuthError> {
        let id = id.to_string();
        let mut conn = self.conn().await?;

        conn.transaction::<_, AuthError, _>(|conn| {
            async move {
                let row: OauthConsentFlowRow = oauth_consent_flow::table
                    .find(&id)
                    .select(OauthConsentFlowRow::as_select())
                    .for_update()
                    .first(conn)
                    .await
                    .map_err(|e| match e {
                        diesel::result::Error::NotFound => AuthError::NotFound,
                        other => AuthError::Internal(other.into()),
                    })?;

                if row.decided_at.is_some() || row.expires_at < Utc::now() {
                    return Err(AuthError::SessionExpired);
                }

                diesel::update(oauth_consent_flow::table.find(&id))
                    .set(oauth_consent_flow::decided_at.eq(Utc::now()))
                    .execute(conn)
                    .await
                    .map_err(|e| AuthError::Internal(e.into()))?;

                Ok(row_to_consent_flow(row))
            }
            .scope_boxed()
        })
        .await
    }

    pub async fn gc_expired_consent_flows(&self) -> Result<u64, AuthError> {
        let mut conn = self.conn().await?;
        let deleted =
            diesel::delete(oauth_consent_flow::table.filter(oauth_consent_flow::expires_at.lt(Utc::now())))
                .execute(&mut conn)
                .await
                .map_err(|e| AuthError::Internal(e.into()))?;
        Ok(deleted as u64)
    }
}

/// What the authorize handler hands over when it needs a screen.
#[derive(Debug, Clone)]
pub struct ConsentFlowRequest {
    pub client_id: String,
    pub identity_id: IdentityId,
    pub session_id: uuid::Uuid,
    pub resource_uri: String,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

fn row_to_consent_flow(row: OauthConsentFlowRow) -> ConsentFlow {
    ConsentFlow {
        id: row.id,
        client_id: row.client_id,
        identity_id: IdentityId::from_uuid(row.identity_id),
        session_id: row.session_id,
        resource_uri: row.resource_uri,
        scopes: row.scopes,
        redirect_uri: row.redirect_uri,
        state: row.state,
        nonce: row.nonce,
        code_challenge: row.code_challenge,
        code_challenge_method: row.code_challenge_method,
        csrf_token: row.csrf_token,
        expires_at: row.expires_at,
    }
}
