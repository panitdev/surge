use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::models::{LoginFlowRow, NewLoginFlow};
use crate::schema::login_flow;
use crate::types::*;
use crate::Engine;

const FLOW_TTL_MINUTES: i64 = 10;
const FLOW_MAX_ATTEMPTS: i32 = 5;

pub struct FlowInfo {
    pub id: String,
    pub return_to: Option<String>,
    pub csrf_token: String,
    pub state: String,
    pub attempts: i32,
    pub error: Option<String>,
    /// The password-verified identity, set when the flow transitions to
    /// `awaiting_totp` (the mandatory second-factor step). `None` otherwise.
    pub identity_id: Option<IdentityId>,
}

impl Engine {
    pub async fn create_login_flow(&self, return_to: Option<&str>) -> Result<FlowInfo, AuthError> {
        let mut conn = self.conn().await?;
        let flow_id = FlowId::generate();
        let csrf = FlowId::generate();
        let now = Utc::now();
        let expires = now + Duration::minutes(FLOW_TTL_MINUTES);

        let new = NewLoginFlow {
            id: flow_id.as_str(),
            return_to,
            csrf_token: csrf.as_str(),
            state: "created",
            attempts: 0,
            error: None,
            expires_at: expires,
            created_at: now,
        };

        diesel::insert_into(login_flow::table)
            .values(&new)
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(FlowInfo {
            id: flow_id.as_str().to_string(),
            return_to: return_to.map(|s| s.to_string()),
            csrf_token: csrf.as_str().to_string(),
            state: "created".to_string(),
            attempts: 0,
            error: None,
            identity_id: None,
        })
    }

    pub async fn get_login_flow(&self, id: &str) -> Result<FlowInfo, AuthError> {
        let mut conn = self.conn().await?;
        let now = Utc::now();

        let row: LoginFlowRow = login_flow::table
            .find(id)
            .select(LoginFlowRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::NotFound => AuthError::NotFound,
                other => AuthError::Internal(other.into()),
            })?;

        if row.expires_at < now || row.attempts >= FLOW_MAX_ATTEMPTS {
            if row.state == "created" {
                diesel::update(login_flow::table.find(id))
                    .set(login_flow::state.eq("expired"))
                    .execute(&mut conn)
                    .await
                    .map_err(|e| AuthError::Internal(e.into()))?;
            }
            return Err(AuthError::SessionExpired);
        }

        Ok(FlowInfo {
            id: row.id,
            return_to: row.return_to,
            csrf_token: row.csrf_token,
            state: row.state,
            attempts: row.attempts,
            error: row.error,
            identity_id: row.identity_id.map(IdentityId::from_uuid),
        })
    }

    /// Transition a `created` flow to `awaiting_totp`, recording the
    /// password-verified identity so the subsequent `POST /flows/{id}/totp`
    /// step knows whom to challenge. No session is minted until that step.
    pub async fn set_flow_awaiting_totp(
        &self,
        id: &str,
        identity_id: IdentityId,
    ) -> Result<(), AuthError> {
        let mut conn = self.conn().await?;

        diesel::update(login_flow::table.find(id))
            .set((
                login_flow::state.eq("awaiting_totp"),
                login_flow::identity_id.eq(*identity_id.as_uuid()),
            ))
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(())
    }

    pub async fn record_flow_error(&self, id: &str, error: &str) -> Result<(), AuthError> {
        let mut conn = self.conn().await?;

        diesel::update(login_flow::table.find(id))
            .set((
                login_flow::attempts.eq(login_flow::attempts + 1),
                login_flow::error.eq(error),
            ))
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(())
    }

    pub async fn complete_flow(&self, id: &str) -> Result<(), AuthError> {
        let mut conn = self.conn().await?;

        diesel::update(login_flow::table.find(id))
            .set(login_flow::state.eq("completed"))
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(())
    }

    pub async fn gc_expired_login_flows(&self) -> Result<u64, AuthError> {
        let mut conn = self.conn().await?;
        let now = Utc::now();

        let deleted = diesel::delete(login_flow::table.filter(login_flow::expires_at.lt(now)))
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(deleted as u64)
    }
}
