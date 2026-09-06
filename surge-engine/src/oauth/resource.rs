//! The audience registry. This table is the whole reason the AS lives inside
//! Surge: a `resource` parameter is valid iff it resolves to a row here, and
//! the row points at the `service` that owns the resource server — a join no
//! external authorization server can perform.

use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use super::{now, OauthResource};
use crate::models::{NewOauthResource, OauthResourceRow};
use crate::schema::oauth_resource;
use crate::types::*;
use crate::Engine;

impl Engine {
    pub async fn create_oauth_resource(
        &self,
        resource_uri: &str,
        service_id: uuid::Uuid,
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
        let created_at = now();

        let mut conn = self.conn().await?;
        diesel::insert_into(oauth_resource::table)
            .values(&NewOauthResource {
                resource_uri: &canonical,
                service_id,
                scopes: scopes.clone(),
                scope_descriptions: scope_descriptions.clone(),
                created_at,
            })
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(OauthResource {
            resource_uri: canonical,
            service_id,
            scopes,
            scope_descriptions,
            created_at,
        })
    }

    pub async fn get_oauth_resource(&self, resource_uri: &str) -> Result<OauthResource, AuthError> {
        let canonical = canonicalize_resource_uri(resource_uri)?;
        let mut conn = self.conn().await?;
        let row: OauthResourceRow = oauth_resource::table
            .find(&canonical)
            .select(OauthResourceRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::NotFound => AuthError::NotFound,
                other => AuthError::Internal(other.into()),
            })?;
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

    /// Resources a given service owns — the introspection authorization
    /// check: a service may only ask about tokens for its own audiences.
    pub async fn oauth_resources_for_service(
        &self,
        service_id: uuid::Uuid,
    ) -> Result<Vec<OauthResource>, AuthError> {
        let mut conn = self.conn().await?;
        let rows: Vec<OauthResourceRow> = oauth_resource::table
            .filter(oauth_resource::service_id.eq(service_id))
            .select(OauthResourceRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;
        Ok(rows.into_iter().map(row_to_resource).collect())
    }

    pub async fn delete_oauth_resource(&self, resource_uri: &str) -> Result<(), AuthError> {
        let canonical = canonicalize_resource_uri(resource_uri)?;
        let mut conn = self.conn().await?;
        let deleted = diesel::delete(oauth_resource::table.find(&canonical))
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

fn row_to_resource(row: OauthResourceRow) -> OauthResource {
    OauthResource {
        resource_uri: row.resource_uri,
        service_id: row.service_id,
        scopes: row.scopes,
        scope_descriptions: row.scope_descriptions,
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
