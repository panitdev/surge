//! Client registry. Admin-registered and dynamically registered clients share
//! one table and one set of rules; the difference is `registration_source`,
//! which is immutable, and what it forbids.

use chrono::Utc;
use diesel::prelude::*;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, RunQueryDsl};

use super::resource::{canonicalize_resource_uri, row_to_resource};
use super::{now, NewOauthClient, OauthClient, RegistrationSource};
use crate::models::{NewOauthClient as NewOauthClientRow, OauthClientRow, OauthResourceRow};
use crate::schema::{oauth_client, oauth_client_audience, oauth_refresh_token, oauth_resource};
use crate::types::*;
use crate::Engine;

/// A client name is attacker-supplied text for a dynamically registered
/// client, and it is rendered on a consent screen. Bounding it is not
/// cosmetic: an unbounded name is a defacement vector on the one screen whose
/// legibility is a security control.
const MAX_CLIENT_NAME_LEN: usize = 120;
const MAX_URI_LEN: usize = 2000;
const MAX_REDIRECT_URIS: usize = 10;

impl Engine {
    pub async fn create_oauth_client(
        &self,
        spec: NewOauthClient,
    ) -> Result<(OauthClient, Option<ClientSecret>), AuthError> {
        validate_client(&spec)?;
        let audiences = spec
            .audiences
            .as_deref()
            .map(canonical_audiences)
            .transpose()?;

        let client_id = ClientId::generate();
        let secret = spec.confidential.then(ClientSecret::generate);
        let created_at = now();

        let row = NewOauthClientRow {
            client_id: client_id.as_str(),
            client_secret_hash: secret.as_ref().map(|s| s.hash()),
            client_name: &spec.client_name,
            client_uri: spec.client_uri.as_deref(),
            logo_uri: spec.logo_uri.as_deref(),
            redirect_uris: spec.redirect_uris.clone(),
            grant_types: spec.grant_types.clone(),
            scopes: spec.scopes.clone(),
            token_endpoint_auth_method: if spec.confidential {
                "client_secret_basic"
            } else {
                "none"
            },
            registration_source: spec.registration_source.as_str(),
            first_party: spec.first_party,
            trust_state: if spec.first_party { "trusted" } else { "untrusted" },
            created_at,
            audience_restricted: audiences.is_some(),
        };

        let token_endpoint_auth_method = row.token_endpoint_auth_method.to_string();
        let trust_state = row.trust_state.to_string();
        let client = OauthClient {
            client_id: client_id.as_str().to_string(),
            client_name: spec.client_name.clone(),
            client_uri: spec.client_uri.clone(),
            logo_uri: spec.logo_uri.clone(),
            redirect_uris: spec.redirect_uris.clone(),
            grant_types: spec.grant_types.clone(),
            scopes: spec.scopes.clone(),
            token_endpoint_auth_method,
            registration_source: spec.registration_source,
            first_party: spec.first_party,
            trust_state,
            confidential: spec.confidential,
            audiences,
            created_at,
        };

        let mut conn = self.conn().await?;
        let row_ref = &row;
        let client_ref = &client;
        conn.transaction::<_, AuthError, _>(|conn| {
            async move {
                diesel::insert_into(oauth_client::table)
                    .values(row_ref)
                    .execute(conn)
                    .await
                    .map_err(|e| AuthError::Internal(e.into()))?;
                if let Some(uris) = &client_ref.audiences {
                    approve_audiences(conn, client_ref, uris).await?;
                }
                Ok(())
            }
            .scope_boxed()
        })
        .await?;

        Ok((client, secret))
    }

    /// Look up a live client. A revoked client is `NotFound`: nothing outside
    /// the admin surface should be able to tell the difference between "never
    /// existed" and "was shut off".
    pub async fn get_oauth_client(&self, client_id: &str) -> Result<OauthClient, AuthError> {
        let mut conn = self.conn().await?;
        let row: OauthClientRow = oauth_client::table
            .find(client_id)
            .filter(oauth_client::revoked_at.is_null())
            .select(OauthClientRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::NotFound => AuthError::NotFound,
                other => AuthError::Internal(other.into()),
            })?;
        Ok(rows_to_clients(&mut conn, vec![row]).await?.remove(0))
    }

    pub async fn list_oauth_clients(&self) -> Result<Vec<OauthClient>, AuthError> {
        let mut conn = self.conn().await?;
        let rows: Vec<OauthClientRow> = oauth_client::table
            .filter(oauth_client::revoked_at.is_null())
            .order(oauth_client::created_at.desc())
            .select(OauthClientRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;
        rows_to_clients(&mut conn, rows).await
    }

    /// Authenticate a confidential client at the token endpoint. A public
    /// client (no stored secret) presenting one is rejected rather than
    /// silently accepted — the auth method a client registered with is the
    /// method it must keep using.
    pub async fn verify_client_secret(
        &self,
        client_id: &str,
        secret: &ClientSecret,
    ) -> Result<OauthClient, AuthError> {
        let mut conn = self.conn().await?;
        let row: OauthClientRow = oauth_client::table
            .find(client_id)
            .filter(oauth_client::revoked_at.is_null())
            .select(OauthClientRow::as_select())
            .first(&mut conn)
            .await
            .map_err(|e| match e {
                diesel::result::Error::NotFound => AuthError::InvalidCredentials,
                other => AuthError::Internal(other.into()),
            })?;

        let stored = row.client_secret_hash.as_ref().ok_or(AuthError::InvalidCredentials)?;
        if !constant_time_eq(stored, &secret.hash()) {
            return Err(AuthError::InvalidCredentials);
        }
        Ok(rows_to_clients(&mut conn, vec![row]).await?.remove(0))
    }

    /// Revoking a client kills its outstanding grants in the same
    /// transaction. A client that can no longer authorize but whose refresh
    /// tokens still mint access tokens is not revoked in any sense a user
    /// would recognize.
    pub async fn revoke_oauth_client(&self, client_id: &str) -> Result<(), AuthError> {
        let mut conn = self.conn().await?;
        let at = now();
        let client_id = client_id.to_string();

        conn.transaction::<_, AuthError, _>(|conn| {
            async move {
                let affected = diesel::update(
                    oauth_client::table
                        .find(&client_id)
                        .filter(oauth_client::revoked_at.is_null()),
                )
                .set(oauth_client::revoked_at.eq(at))
                .execute(conn)
                .await
                .map_err(|e| AuthError::Internal(e.into()))?;

                if affected == 0 {
                    return Err(AuthError::NotFound);
                }

                diesel::update(
                    oauth_refresh_token::table
                        .filter(oauth_refresh_token::client_id.eq(&client_id))
                        .filter(oauth_refresh_token::revoked_at.is_null()),
                )
                .set(oauth_refresh_token::revoked_at.eq(at))
                .execute(conn)
                .await
                .map_err(|e| AuthError::Internal(e.into()))?;

                Ok(())
            }
            .scope_boxed()
        })
        .await
    }

    /// Records that a client completed an authorization. Feeds the dynamic
    /// client sweep, which is the only thing keeping an open registration
    /// endpoint from accumulating rows forever.
    pub async fn touch_oauth_client(&self, client_id: &str) -> Result<(), AuthError> {
        let mut conn = self.conn().await?;
        diesel::update(oauth_client::table.find(client_id))
            .set(oauth_client::last_used_at.eq(now()))
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;
        Ok(())
    }

    /// Deletes dynamically registered clients that never completed an
    /// authorization within the TTL. Admin-registered clients are never
    /// swept: an operator registering a client ahead of the service that will
    /// use it is a normal thing to do.
    pub async fn gc_unused_dynamic_clients(
        &self,
        ttl: std::time::Duration,
    ) -> Result<u64, AuthError> {
        let cutoff = Utc::now()
            - chrono::Duration::from_std(ttl)
                .map_err(|e| AuthError::Internal(anyhow::anyhow!("dcr ttl out of range: {e}")))?;
        let mut conn = self.conn().await?;

        let deleted = diesel::delete(
            oauth_client::table
                .filter(oauth_client::registration_source.eq("dynamic"))
                .filter(oauth_client::last_used_at.is_null())
                .filter(oauth_client::created_at.lt(cutoff)),
        )
        .execute(&mut conn)
        .await
        .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(deleted as u64)
    }
}

/// Canonicalizes and de-duplicates the URIs a client is to be approved for.
fn canonical_audiences(uris: &[String]) -> Result<Vec<String>, AuthError> {
    let mut canonical = uris
        .iter()
        .map(|uri| canonicalize_resource_uri(uri))
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort();
    canonical.dedup();
    Ok(canonical)
}

/// Records approvals against the registrations that hold `uris` right now.
/// Every URI must resolve, and the client must be eligible for each under the
/// shared rule; the approval names the registration id, so a URI that is
/// later deleted and registered again is not approved.
async fn approve_audiences(
    conn: &mut diesel_async::AsyncPgConnection,
    client: &OauthClient,
    uris: &[String],
) -> Result<(), AuthError> {
    let resources: Vec<OauthResourceRow> = oauth_resource::table
        .filter(oauth_resource::resource_uri.eq_any(uris))
        .select(OauthResourceRow::as_select())
        .for_share()
        .load(conn)
        .await
        .map_err(|e| AuthError::Internal(e.into()))?;
    if resources.len() != uris.len() {
        return Err(field(
            "audiences",
            "every audience must be a registered resource",
        ));
    }
    let resources: Vec<_> = resources.into_iter().map(row_to_resource).collect();
    if let Some(denied) = resources
        .iter()
        .find(|resource| !super::client_may_use_resource(client, resource))
    {
        return Err(field(
            "audiences",
            format!(
                "this client may not be bound to {}: it is delegated and has not opted in to \
                 dynamic registration",
                denied.resource_uri
            ),
        ));
    }
    let rows: Vec<_> = resources
        .iter()
        .map(|resource| {
            (
                oauth_client_audience::client_id.eq(&client.client_id),
                oauth_client_audience::registration_id.eq(resource.registration_id),
            )
        })
        .collect();
    diesel::insert_into(oauth_client_audience::table)
        .values(rows)
        .execute(conn)
        .await
        .map_err(|e| AuthError::Internal(e.into()))?;
    Ok(())
}

/// Maps rows to clients, translating approvals for restricted clients back
/// to the canonical URIs of the registrations they name.
pub(crate) async fn rows_to_clients(
    conn: &mut diesel_async::AsyncPgConnection,
    rows: Vec<OauthClientRow>,
) -> Result<Vec<OauthClient>, AuthError> {
    let restricted: Vec<&str> = rows
        .iter()
        .filter(|row| row.audience_restricted)
        .map(|row| row.client_id.as_str())
        .collect();
    let mut approved: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    if !restricted.is_empty() {
        let pairs: Vec<(String, String)> = oauth_client_audience::table
            .inner_join(oauth_resource::table)
            .filter(oauth_client_audience::client_id.eq_any(&restricted))
            .order(oauth_resource::resource_uri.asc())
            .select((oauth_client_audience::client_id, oauth_resource::resource_uri))
            .load(conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;
        for (client_id, uri) in pairs {
            approved.entry(client_id).or_default().push(uri);
        }
    }
    Ok(rows
        .into_iter()
        .map(|row| {
            let audiences = row
                .audience_restricted
                .then(|| approved.remove(&row.client_id).unwrap_or_default());
            row_to_client(row, audiences)
        })
        .collect())
}

fn row_to_client(row: OauthClientRow, audiences: Option<Vec<String>>) -> OauthClient {
    OauthClient {
        client_id: row.client_id,
        client_name: row.client_name,
        client_uri: row.client_uri,
        logo_uri: row.logo_uri,
        redirect_uris: row.redirect_uris,
        grant_types: row.grant_types,
        scopes: row.scopes,
        token_endpoint_auth_method: row.token_endpoint_auth_method,
        registration_source: RegistrationSource::from_db(&row.registration_source),
        first_party: row.first_party,
        trust_state: row.trust_state,
        confidential: row.client_secret_hash.is_some(),
        audiences,
        created_at: row.created_at,
    }
}

fn field(field: &'static str, message: impl Into<String>) -> AuthError {
    AuthError::Validation(ValidationError::Field {
        field,
        message: message.into(),
    })
}

fn validate_client(spec: &NewOauthClient) -> Result<(), AuthError> {
    if spec.client_name.trim().is_empty() {
        return Err(field("client_name", "must not be empty"));
    }
    if spec.client_name.len() > MAX_CLIENT_NAME_LEN {
        return Err(field(
            "client_name",
            format!("must be at most {MAX_CLIENT_NAME_LEN} bytes"),
        ));
    }
    for (name, uri) in [("client_uri", &spec.client_uri), ("logo_uri", &spec.logo_uri)] {
        if let Some(uri) = uri {
            if uri.len() > MAX_URI_LEN {
                return Err(field(name, format!("must be at most {MAX_URI_LEN} bytes")));
            }
            let parsed = url::Url::parse(uri).map_err(|_| field(name, "invalid URL"))?;
            if parsed.scheme() != "https" && parsed.scheme() != "http" {
                return Err(field(name, "must be http(s)"));
            }
        }
    }
    if spec.redirect_uris.is_empty() {
        return Err(field("redirect_uris", "at least one is required"));
    }
    if spec.redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(field(
            "redirect_uris",
            format!("at most {MAX_REDIRECT_URIS} are allowed"),
        ));
    }
    for uri in &spec.redirect_uris {
        validate_redirect_uri(uri)?;
    }
    if spec.registration_source == RegistrationSource::Dynamic && spec.first_party {
        return Err(field(
            "first_party",
            "a dynamically registered client can never be first-party",
        ));
    }
    for grant in &spec.grant_types {
        if !matches!(grant.as_str(), "authorization_code" | "refresh_token") {
            return Err(field(
                "grant_types",
                format!("unsupported grant type: {grant}"),
            ));
        }
    }
    if !spec.grant_types.iter().any(|g| g == "authorization_code") {
        return Err(field(
            "grant_types",
            "authorization_code is the only way to obtain a token here, so it is required",
        ));
    }
    Ok(())
}

/// `https`, or `http` on a loopback host with any port — the native-app case
/// MCP clients need. No wildcards and no `http` on a public host: both turn
/// the redirect into an interception point, and neither has a legitimate use
/// that a loopback or `https` URI doesn't cover.
pub fn validate_redirect_uri(uri: &str) -> Result<(), AuthError> {
    if uri.len() > MAX_URI_LEN {
        return Err(field(
            "redirect_uris",
            format!("must be at most {MAX_URI_LEN} bytes"),
        ));
    }
    if uri.contains('*') {
        return Err(field("redirect_uris", "wildcards are not allowed"));
    }
    let parsed = url::Url::parse(uri).map_err(|_| field("redirect_uris", "invalid URL"))?;
    if parsed.fragment().is_some() {
        return Err(field("redirect_uris", "must not carry a fragment"));
    }
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = parsed.host_str().unwrap_or("");
            if matches!(host, "127.0.0.1" | "::1" | "[::1]" | "localhost") {
                Ok(())
            } else {
                Err(field(
                    "redirect_uris",
                    "http is only allowed on a loopback host (127.0.0.1, ::1, localhost)",
                ))
            }
        }
        other => Err(field(
            "redirect_uris",
            format!("unsupported scheme: {other}"),
        )),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uris_allow_https_and_loopback_http_only() {
        assert!(validate_redirect_uri("https://client.example/cb").is_ok());
        assert!(validate_redirect_uri("http://127.0.0.1:53821/cb").is_ok());
        assert!(validate_redirect_uri("http://[::1]:9000/cb").is_ok());

        assert!(validate_redirect_uri("http://client.example/cb").is_err());
        assert!(validate_redirect_uri("https://*.example/cb").is_err());
        assert!(validate_redirect_uri("ftp://client.example/cb").is_err());
        assert!(validate_redirect_uri("https://client.example/cb#frag").is_err());
        assert!(validate_redirect_uri("not a url").is_err());
    }

    #[test]
    fn a_dynamic_client_can_never_be_first_party() {
        let spec = NewOauthClient {
            client_name: "Impostor".into(),
            client_uri: None,
            logo_uri: None,
            redirect_uris: vec!["https://client.example/cb".into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec![],
            confidential: false,
            first_party: true,
            registration_source: RegistrationSource::Dynamic,
            audiences: None,
        };
        assert!(validate_client(&spec).is_err());
    }
}
