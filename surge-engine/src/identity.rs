use chrono::Utc;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use url::Url;

use crate::models::{IdentityRow, NewIdentity};
use crate::schema::identity;
use crate::types::*;
use crate::Engine;

impl Engine {
    pub async fn create_identity(
        &self,
        username: &Username,
        display_name: &str,
    ) -> Result<Identity, AuthError> {
        let mut conn = self.conn().await?;
        insert_identity(&mut conn, username, display_name).await
    }

    pub async fn get_identity(&self, id: IdentityId) -> Result<Identity, AuthError> {
        let mut conn = self.conn().await?;

        let row: IdentityRow = identity::table
            .find(*id.as_uuid())
            .select(IdentityRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::NotFound => AuthError::NotFound,
                other => AuthError::Internal(other.into()),
            })?;

        row_to_identity(row)
    }

    pub async fn get_identity_by_username(
        &self,
        username: &Username,
    ) -> Result<Identity, AuthError> {
        let mut conn = self.conn().await?;

        let row: IdentityRow = identity::table
            .filter(identity::username.eq(username.as_str()))
            .select(IdentityRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::NotFound => AuthError::NotFound,
                other => AuthError::Internal(other.into()),
            })?;

        row_to_identity(row)
    }

    pub async fn update_profile(
        &self,
        id: IdentityId,
        patch: &ProfilePatch,
    ) -> Result<Identity, AuthError> {
        let mut conn = self.conn().await?;
        let now = Utc::now();

        if let Some(ref name) = patch.display_name {
            diesel::update(identity::table.find(*id.as_uuid()))
                .set((
                    identity::display_name.eq(name),
                    identity::updated_at.eq(now),
                ))
                .execute(&mut conn)
                .await
                .map_err(|e| AuthError::Internal(e.into()))?;
        }

        if let Some(ref avatar) = patch.avatar_url {
            let url_str = avatar.as_ref().map(|u| u.to_string());
            diesel::update(identity::table.find(*id.as_uuid()))
                .set((
                    identity::avatar_url.eq(url_str),
                    identity::updated_at.eq(now),
                ))
                .execute(&mut conn)
                .await
                .map_err(|e| AuthError::Internal(e.into()))?;
        }

        self.get_identity(id).await
    }

    pub async fn set_identity_state(
        &self,
        id: IdentityId,
        state: IdentityState,
    ) -> Result<(), AuthError> {
        let mut conn = self.conn().await?;

        let affected = diesel::update(identity::table.find(*id.as_uuid()))
            .set((
                identity::state.eq(state.to_string()),
                identity::updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        if affected == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }
}

/// Connection-taking core of [`Engine::create_identity`], reused inside the
/// atomic `create_identity_and_session` transaction (session.rs) so the
/// identity insert shares one connection/transaction with the rest.
pub(crate) async fn insert_identity(
    conn: &mut AsyncPgConnection,
    username: &Username,
    display_name: &str,
) -> Result<Identity, AuthError> {
    let now = Utc::now();
    let id = IdentityId::new();

    let new = NewIdentity {
        id: *id.as_uuid(),
        username: username.as_str(),
        display_name,
        avatar_url: None,
        state: "active",
        created_at: now,
        updated_at: now,
    };

    diesel::insert_into(identity::table)
        .values(&new)
        .execute(conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => AuthError::UsernameTaken,
            other => AuthError::Internal(other.into()),
        })?;

    Ok(Identity {
        id,
        username: username.clone(),
        display_name: display_name.to_string(),
        avatar_url: None,
        state: IdentityState::Active,
        created_at: now,
        updated_at: now,
    })
}

pub(crate) fn row_to_identity(row: IdentityRow) -> Result<Identity, AuthError> {
    let state: IdentityState = row
        .state
        .parse()
        .map_err(|e: String| AuthError::Internal(anyhow::anyhow!(e)))?;

    let avatar_url = row
        .avatar_url
        .as_deref()
        .map(|s| Url::parse(s))
        .transpose()
        .map_err(|e| AuthError::Internal(e.into()))?;

    Ok(Identity {
        id: IdentityId::from_uuid(row.id),
        username: Username::new(row.username.as_str())
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("stored username invalid: {e}")))?,
        display_name: row.display_name,
        avatar_url,
        state,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}
