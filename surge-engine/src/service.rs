use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::models::{NewService, ServiceRow};
use crate::schema::service;
use crate::types::*;
use crate::Engine;

pub struct ServiceInfo {
    pub id: uuid::Uuid,
    pub name: String,
    pub grants: Vec<String>,
    pub return_origins: Vec<String>,
}

impl Engine {
    pub async fn create_service(
        &self,
        name: &str,
        token_hash: Vec<u8>,
        grants: Vec<String>,
        return_origins: Vec<String>,
    ) -> Result<ServiceInfo, AuthError> {
        let mut conn = self.conn().await?;
        let id = ServiceId::new();
        let now = Utc::now();

        let new = NewService {
            id: *id.as_uuid(),
            name,
            token_hash,
            grants: grants.clone(),
            return_origins: return_origins.clone(),
            created_at: now,
        };

        diesel::insert_into(service::table)
            .values(&new)
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(ServiceInfo {
            id: *id.as_uuid(),
            name: name.to_string(),
            grants,
            return_origins,
        })
    }

    pub async fn verify_service_token(&self, token_hash: &[u8]) -> Result<ServiceInfo, AuthError> {
        let mut conn = self.conn().await?;

        let row: ServiceRow = service::table
            .filter(service::token_hash.eq(token_hash))
            .filter(service::revoked_at.is_null())
            .select(ServiceRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::NotFound => AuthError::InvalidToken,
                other => AuthError::Internal(other.into()),
            })?;

        Ok(ServiceInfo {
            id: row.id,
            name: row.name,
            grants: row.grants,
            return_origins: row.return_origins,
        })
    }

    pub async fn list_services(&self) -> Result<Vec<ServiceInfo>, AuthError> {
        let mut conn = self.conn().await?;

        let rows: Vec<ServiceRow> = service::table
            .filter(service::revoked_at.is_null())
            .select(ServiceRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(rows
            .into_iter()
            .map(|r| ServiceInfo {
                id: r.id,
                name: r.name,
                grants: r.grants,
                return_origins: r.return_origins,
            })
            .collect())
    }

    pub async fn revoke_service(&self, name: &str) -> Result<(), AuthError> {
        let mut conn = self.conn().await?;

        let affected = diesel::update(
            service::table
                .filter(service::name.eq(name))
                .filter(service::revoked_at.is_null()),
        )
        .set(service::revoked_at.eq(Utc::now()))
        .execute(&mut conn)
        .await
        .map_err(|e| AuthError::Internal(e.into()))?;

        if affected == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    pub async fn all_return_origins(&self) -> Result<Vec<String>, AuthError> {
        let services = self.list_services().await?;
        Ok(services
            .into_iter()
            .flat_map(|s| s.return_origins)
            .collect())
    }
}
