//! The audience registry. This table is the whole reason the AS lives inside
//! Surge: a `resource` parameter is valid iff it resolves to a row here, and
//! the row points at the `service` that owns the resource server — a join no
//! external authorization server can perform.

use crate::audit::{audit_conn, AuditActor};
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error};
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

use super::{now, OauthResource, ResourceSource};
use crate::models::{NewOauthResource, OauthResourceRow};
use crate::schema::oauth_resource;
use crate::types::*;
use crate::Engine;

impl Engine {
    /// Registers a service resource with no recorded registrar — the
    /// operator path (`surge-server oauth resource create`).
    pub async fn create_oauth_resource(
        &self,
        resource_uri: &str,
        service_id: Uuid,
        scopes: Vec<String>,
        scope_descriptions: serde_json::Value,
    ) -> Result<OauthResource, AuthError> {
        let mut conn = self.conn().await?;
        insert_resource(
            &mut conn,
            resource_uri,
            Some(service_id),
            None,
            scopes,
            scope_descriptions,
        )
        .await
    }

    /// Registers a resource on behalf of an authenticated service, which is
    /// recorded as the registrar whoever ends up owning it. `owner` is the
    /// owning service of a service registration; `None` registers a
    /// delegated resource, which no service owns.
    pub async fn register_oauth_resource(
        &self,
        actor: AuditActor,
        registrar_service_id: Uuid,
        resource_uri: &str,
        owner: Option<Uuid>,
        scopes: Vec<String>,
        scope_descriptions: serde_json::Value,
    ) -> Result<OauthResource, AuthError> {
        let mut conn = self.conn().await?;
        conn.transaction(|conn| {
            async move {
                let resource = insert_resource(
                    conn,
                    resource_uri,
                    owner,
                    Some(registrar_service_id),
                    scopes,
                    scope_descriptions,
                )
                .await?;
                audit_conn(
                    conn,
                    actor,
                    "create_oauth_resource",
                    serde_json::json!({
                        "registration_id": resource.registration_id,
                        "resource_uri": resource.resource_uri,
                        "registration_source": resource.registration_source,
                        "owner_service_id": owner,
                        "registrar_service_id": registrar_service_id,
                    }),
                    None,
                )
                .await?;
                Ok(resource)
            }
            .scope_boxed()
        })
        .await
    }

    /// The registration currently holding a canonical URI.
    pub async fn get_oauth_resource(&self, resource_uri: &str) -> Result<OauthResource, AuthError> {
        let canonical = canonicalize_resource_uri(resource_uri)?;
        let mut conn = self.conn().await?;
        let row: OauthResourceRow = oauth_resource::table
            .filter(oauth_resource::resource_uri.eq(&canonical))
            .select(OauthResourceRow::as_select())
            .first(&mut conn)
            .await
            .map_err(not_found)?;
        Ok(row_to_resource(row))
    }

    /// One registration by its immutable id. `NotFound` once it has been
    /// deleted, even if its URI has since been registered again.
    pub async fn get_oauth_registration(
        &self,
        registration_id: Uuid,
    ) -> Result<OauthResource, AuthError> {
        let mut conn = self.conn().await?;
        let row: OauthResourceRow = oauth_resource::table
            .find(registration_id)
            .select(OauthResourceRow::as_select())
            .first(&mut conn)
            .await
            .map_err(not_found)?;
        Ok(row_to_resource(row))
    }

    pub async fn list_oauth_resources(&self) -> Result<Vec<OauthResource>, AuthError> {
        let mut conn = self.conn().await?;
        let rows: Vec<OauthResourceRow> = oauth_resource::table
            .order(oauth_resource::resource_uri.asc())
            .select(OauthResourceRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;
        Ok(rows.into_iter().map(row_to_resource).collect())
    }

    /// Registrations a service created, whoever owns them — the set a
    /// delegated registrar may see and manage.
    pub async fn oauth_resources_for_registrar(
        &self,
        registrar_service_id: Uuid,
    ) -> Result<Vec<OauthResource>, AuthError> {
        let mut conn = self.conn().await?;
        let rows: Vec<OauthResourceRow> = oauth_resource::table
            .filter(oauth_resource::registrar_service_id.eq(registrar_service_id))
            .order(oauth_resource::resource_uri.asc())
            .select(OauthResourceRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;
        Ok(rows.into_iter().map(row_to_resource).collect())
    }

    /// Service registrations a given service owns — the introspection
    /// authorization check: a service may only ask about tokens for its own
    /// audiences.
    pub async fn oauth_resources_for_service(
        &self,
        service_id: Uuid,
    ) -> Result<Vec<OauthResource>, AuthError> {
        let mut conn = self.conn().await?;
        let rows: Vec<OauthResourceRow> = oauth_resource::table
            .filter(oauth_resource::service_id.eq(service_id))
            .filter(oauth_resource::registration_source.eq(ResourceSource::Service.as_str()))
            .select(OauthResourceRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;
        Ok(rows.into_iter().map(row_to_resource).collect())
    }

    /// Deletes the registration holding a URI. Every consent, pending flow,
    /// code, refresh token and client approval bound to it goes with it.
    pub async fn delete_oauth_resource(&self, resource_uri: &str) -> Result<(), AuthError> {
        let canonical = canonicalize_resource_uri(resource_uri)?;
        let mut conn = self.conn().await?;
        let deleted = diesel::delete(
            oauth_resource::table.filter(oauth_resource::resource_uri.eq(&canonical)),
        )
        .execute(&mut conn)
        .await
        .map_err(|e| AuthError::Internal(e.into()))?;
        if deleted == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    pub async fn count_oauth_resources(&self) -> Result<i64, AuthError> {
        let mut conn = self.conn().await?;
        oauth_resource::table
            .count()
            .get_result(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))
    }
}

fn not_found(e: Error) -> AuthError {
    match e {
        Error::NotFound => AuthError::NotFound,
        other => AuthError::Internal(other.into()),
    }
}

async fn insert_resource(
    conn: &mut AsyncPgConnection,
    resource_uri: &str,
    owner: Option<Uuid>,
    registrar_service_id: Option<Uuid>,
    scopes: Vec<String>,
    scope_descriptions: serde_json::Value,
) -> Result<OauthResource, AuthError> {
    let canonical = canonicalize_resource_uri(resource_uri)?;
    if !scope_descriptions.is_object() {
        return Err(AuthError::Validation(ValidationError::Field {
            field: "scope_descriptions",
            message: "must be a JSON object of {scope: description}".into(),
        }));
    }

    let row: OauthResourceRow = diesel::insert_into(oauth_resource::table)
        .values(&NewOauthResource {
            id: Uuid::now_v7(),
            resource_uri: &canonical,
            registration_source: if owner.is_some() {
                ResourceSource::Service
            } else {
                ResourceSource::Delegated
            }
            .as_str(),
            service_id: owner,
            registrar_service_id,
            scopes,
            scope_descriptions,
            allowed_cimd_client_ids: Vec::new(),
            dcr_enabled: false,
            created_at: now(),
        })
        .returning(OauthResourceRow::as_returning())
        .get_result(conn)
        .await
        .map_err(|err| match err {
            Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
                AuthError::ResourceAlreadyRegistered
            }
            Error::DatabaseError(DatabaseErrorKind::ForeignKeyViolation, _) => AuthError::NotFound,
            other => AuthError::Internal(other.into()),
        })?;

    Ok(row_to_resource(row))
}

fn row_to_resource(row: OauthResourceRow) -> OauthResource {
    OauthResource {
        registration_id: row.id,
        resource_uri: row.resource_uri,
        registration_source: ResourceSource::from_db(&row.registration_source),
        service_id: row.service_id,
        registrar_service_id: row.registrar_service_id,
        scopes: row.scopes,
        scope_descriptions: row.scope_descriptions,
        allowed_cimd_client_ids: row.allowed_cimd_client_ids,
        dcr_enabled: row.dcr_enabled,
        created_at: row.created_at,
    }
}

/// RFC 8707 audience URIs are compared, not interpreted — so the comparison
/// has to be exact, and "exact" needs one canonical form or a client that
/// writes a trailing slash gets a token that validates nowhere. Normalizes
/// the trailing slash and rejects anything carrying a fragment or query,
/// which an audience identifier has no business having.
pub fn canonicalize_resource_uri(uri: &str) -> Result<String, AuthError> {
    let invalid = |message: &str| {
        AuthError::Validation(ValidationError::Field {
            field: "resource",
            message: message.to_string(),
        })
    };

    let parsed = url::Url::parse(uri).map_err(|_| invalid("invalid URL"))?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return Err(invalid("must be an http(s) URL"));
    }
    if parsed.fragment().is_some() {
        return Err(invalid("must not carry a fragment"));
    }
    if parsed.query().is_some() {
        return Err(invalid("must not carry a query string"));
    }
    let normalized = parsed.as_str().trim_end_matches('/').to_string();
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_uris_normalize_to_one_comparable_form() {
        assert_eq!(
            canonicalize_resource_uri("https://dispatch.panit.dev/mcp/").unwrap(),
            "https://dispatch.panit.dev/mcp"
        );
        assert_eq!(
            canonicalize_resource_uri("https://dispatch.panit.dev/mcp").unwrap(),
            "https://dispatch.panit.dev/mcp"
        );
    }

    #[test]
    fn an_audience_carries_no_query_or_fragment() {
        assert!(canonicalize_resource_uri("https://a.example/mcp?x=1").is_err());
        assert!(canonicalize_resource_uri("https://a.example/mcp#f").is_err());
        assert!(canonicalize_resource_uri("urn:example:mcp").is_err());
    }
}
