use chrono::Utc;
use diesel_async::RunQueryDsl;

use crate::models::NewAuditEntry;
use crate::schema::audit_log;
use crate::types::AuthError;
use crate::Engine;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum AuditActor {
    Identity { id: String },
    Service { id: String, name: String },
    Operator { name: String },
}

impl Engine {
    pub async fn audit(
        &self,
        actor: AuditActor,
        action: &str,
        subject: serde_json::Value,
        detail: Option<serde_json::Value>,
    ) -> Result<(), AuthError> {
        let mut conn = self.conn().await?;

        let entry = NewAuditEntry {
            at: Utc::now(),
            actor: serde_json::to_value(&actor)
                .map_err(|e| AuthError::Internal(e.into()))?,
            action: action.to_string(),
            subject,
            detail,
        };

        diesel::insert_into(audit_log::table)
            .values(&entry)
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(())
    }
}
