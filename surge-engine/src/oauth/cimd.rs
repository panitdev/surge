//! Client-ID metadata document (CIMD) clients: validation and storage.
//!
//! A CIMD client's ID is the HTTPS URL of a JSON document the client
//! publishes about itself. This module is the pure half — what a document
//! must say, and how a validated one is stored and swept. Fetching it is the
//! router's job (`surge::router::oauth_as`), because it needs a network the
//! engine deliberately does not have.
//!
//! Storage model. Nothing is written when a document is fetched: an
//! authorization request that fails any later check (session, eligibility,
//! scopes) leaves no trace. A row is upserted only inside the transaction
//! that creates the consent flow, under the resource's shared lock, so the
//! grant tables can reference the client. After that every stage (consent,
//! code redemption, refresh) reads the row and the resource's *current*
//! policy and never fetches again. A revoked row is kept as a tombstone: the
//! upsert refuses to resurrect it and the sweep never deletes it.

use chrono::Utc;
use diesel::prelude::*;
use diesel::sql_types::{Array, BigInt, Nullable, Text, Timestamptz};
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

use super::client::{field, validate_client};
use super::{now, NewOauthClient, OauthClient, OauthResource, RegistrationSource};
use crate::schema::oauth_client;
use crate::types::*;
use crate::Engine;

/// The most bytes of a document that are ever read or parsed.
pub const MAX_CIMD_DOCUMENT_BYTES: usize = 32 * 1024;
const MAX_CLIENT_ID_LEN: usize = 1024;
const MAX_SCOPE_TOKENS: usize = 64;
const MAX_URI_LEN: usize = 2000;
const MAX_NAME_LEN: usize = 120;
const MAX_REDIRECTS: usize = 10;

/// A validated client-ID metadata document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CimdMetadata {
    /// The document's URL, which is also its self-declared `client_id`.
    pub client_id: String,
    pub client_name: String,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    /// The `scope` the document declares, if any. A ceiling, never a grant:
    /// the resource decides what exists.
    pub scopes: Option<Vec<String>>,
}

impl CimdMetadata {
    /// The host that publishes the document: who vouches for the metadata,
    /// not proof of who is running the client.
    pub fn publisher_host(&self) -> Option<String> {
        url::Url::parse(&self.client_id)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
    }
}

impl OauthClient {
    /// The in-memory client an authorization request is evaluated as before
    /// any row exists. Untrusted, public, never first-party, no audience
    /// list. Without a declared `scope`, the whole resource is in range.
    pub fn from_cimd(metadata: &CimdMetadata, resource: &OauthResource) -> Self {
        OauthClient {
            client_id: metadata.client_id.clone(),
            client_name: metadata.client_name.clone(),
            client_uri: metadata.client_uri.clone(),
            logo_uri: metadata.logo_uri.clone(),
            redirect_uris: metadata.redirect_uris.clone(),
            grant_types: metadata.grant_types.clone(),
            scopes: metadata
                .scopes
                .clone()
                .unwrap_or_else(|| resource.scopes.clone()),
            token_endpoint_auth_method: "none".into(),
            registration_source: RegistrationSource::Cimd,
            first_party: false,
            trust_state: "untrusted".into(),
            confidential: false,
            audiences: None,
            registrar_service_id: None,
            created_at: now(),
        }
    }
}

/// Checks that `id` is acceptable as a CIMD client ID, and returns why not.
///
/// Exactly what [`url::Url`] would serialize it as: that rejects dot
/// segments, default ports, upper-case hosts and every other spelling that
/// would let two strings name one document (or one string name two). On top
/// of that: `https`, a DNS host (no IP literal, no single-label or
/// local-looking name), no userinfo, no fragment, no explicit port, and a
/// path.
pub fn validate_cimd_client_id(id: &str) -> Result<url::Url, &'static str> {
    if id.len() > MAX_CLIENT_ID_LEN {
        return Err("client_id is too long");
    }
    let parsed = url::Url::parse(id).map_err(|_| "client_id is not a URL")?;
    if parsed.scheme() != "https" {
        return Err("client_id must be an https URL");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("client_id must not carry userinfo");
    }
    if parsed.fragment().is_some() {
        return Err("client_id must not carry a fragment");
    }
    if parsed.path().len() <= 1 {
        return Err("client_id must have a path");
    }
    if parsed.port().is_some() {
        return Err("client_id must use the default https port");
    }
    match parsed.host() {
        Some(url::Host::Domain(host)) => {
            let host = host.trim_end_matches('.');
            let local = host == "localhost"
                || !host.contains('.')
                || [".localhost", ".local", ".internal", ".localdomain", ".home.arpa"]
                    .iter()
                    .any(|suffix| host.ends_with(suffix));
            if local {
                return Err("client_id must name a public host");
            }
        }
        Some(_) => return Err("client_id must not use an IP address"),
        None => return Err("client_id has no host"),
    }
    if parsed.as_str() != id {
        return Err("client_id must be in canonical form");
    }
    Ok(parsed)
}

/// Parses and validates a fetched document.
///
/// Requires the exact self-declared `client_id`, a name, valid redirect URIs
/// and `token_endpoint_auth_method: "none"`. Anything that smells of client
/// authentication (a secret, or any other method) is refused rather than
/// ignored: confidential CIMD clients are not supported, and a document that
/// asks for one must not be quietly downgraded to public.
pub fn parse_cimd_document(client_id: &str, body: &[u8]) -> Result<CimdMetadata, String> {
    validate_cimd_client_id(client_id).map_err(str::to_string)?;
    if body.len() > MAX_CIMD_DOCUMENT_BYTES {
        return Err("document is too large".into());
    }
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "document is not valid JSON".to_string())?;
    let obj = doc.as_object().ok_or("document must be a JSON object")?;

    match obj.get("client_id") {
        Some(serde_json::Value::String(declared)) if declared == client_id => {}
        Some(_) => return Err("client_id does not match the document URL".into()),
        None => return Err("client_id is missing".into()),
    }
    for forbidden in ["client_secret", "client_secret_expires_at"] {
        if obj.contains_key(forbidden) {
            return Err(format!("{forbidden} must not be published"));
        }
    }
    match obj.get("token_endpoint_auth_method") {
        Some(serde_json::Value::String(m)) if m == "none" => {}
        _ => return Err("token_endpoint_auth_method must be \"none\"".into()),
    }

    let string = |key: &str, max: usize| -> Result<Option<String>, String> {
        match obj.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(s)) if s.len() <= max => Ok(Some(s.clone())),
            Some(_) => Err(format!("{key} must be a string of at most {max} bytes")),
        }
    };
    let list = |key: &str, max: usize| -> Result<Option<Vec<String>>, String> {
        match obj.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::Array(items)) if items.len() <= max => items
                .iter()
                .map(|v| v.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .map(Some)
                .ok_or_else(|| format!("{key} must be an array of strings")),
            Some(_) => Err(format!("{key} must be an array of at most {max} strings")),
        }
    };

    let client_name = string("client_name", MAX_NAME_LEN)?
        .filter(|n| !n.trim().is_empty())
        .ok_or("client_name is required")?;
    let redirect_uris = list("redirect_uris", MAX_REDIRECTS)?
        .filter(|u| !u.is_empty())
        .ok_or("redirect_uris is required")?;
    let grant_types =
        list("grant_types", 8)?.unwrap_or_else(|| vec!["authorization_code".to_string()]);
    if let Some(types) = list("response_types", 8)?
        && types != ["code"]
    {
        return Err("response_types must be [\"code\"]".into());
    }
    let scopes = match string("scope", 4096)? {
        Some(s) => {
            let tokens: Vec<String> = s.split_ascii_whitespace().map(str::to_string).collect();
            if tokens.len() > MAX_SCOPE_TOKENS {
                return Err("scope lists too many scopes".into());
            }
            Some(tokens)
        }
        None => None,
    };

    let metadata = CimdMetadata {
        client_id: client_id.to_string(),
        client_name,
        client_uri: string("client_uri", MAX_URI_LEN)?,
        logo_uri: string("logo_uri", MAX_URI_LEN)?,
        redirect_uris,
        grant_types,
        scopes,
    };
    validate_metadata(&metadata).map_err(|e| e.to_string())?;
    Ok(metadata)
}

/// The shared client rules (name length, URL schemes, redirect URI shape,
/// grant types) applied to a CIMD client as to every other. Run again by the
/// engine before it stores anything, so a caller cannot hand it an
/// unvalidated document.
fn validate_metadata(metadata: &CimdMetadata) -> Result<(), AuthError> {
    validate_cimd_client_id(&metadata.client_id).map_err(|m| field("client_id", m))?;
    validate_client(&NewOauthClient {
        client_name: metadata.client_name.clone(),
        client_uri: metadata.client_uri.clone(),
        logo_uri: metadata.logo_uri.clone(),
        redirect_uris: metadata.redirect_uris.clone(),
        grant_types: metadata.grant_types.clone(),
        scopes: vec![],
        confidential: false,
        first_party: false,
        registration_source: RegistrationSource::Cimd,
        audiences: None,
    })
}

/// Upserts the shared client row for a validated document. Must run inside
/// the transaction that creates the consent flow, after the registration is
/// locked. Concurrent upserts converge on one row; a revoked row is never
/// touched and yields `Forbidden`.
pub(super) async fn upsert_cimd_client(
    conn: &mut AsyncPgConnection,
    metadata: &CimdMetadata,
) -> Result<(), AuthError> {
    validate_metadata(metadata)?;
    // Identity, trust and source columns are deliberately not in the update,
    // and the `WHERE` leaves a revoked tombstone untouched.
    let changed = diesel::sql_query(
        "INSERT INTO surge.oauth_client \
            (client_id, client_secret_hash, client_name, client_uri, logo_uri, redirect_uris, \
             grant_types, scopes, token_endpoint_auth_method, registration_source, \
             first_party, trust_state, created_at, audience_restricted) \
         VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, 'none', 'cimd', FALSE, 'untrusted', $8, FALSE) \
         ON CONFLICT (client_id) DO UPDATE SET \
            client_name = EXCLUDED.client_name, client_uri = EXCLUDED.client_uri, \
            logo_uri = EXCLUDED.logo_uri, redirect_uris = EXCLUDED.redirect_uris, \
            grant_types = EXCLUDED.grant_types, scopes = EXCLUDED.scopes \
          WHERE surge.oauth_client.revoked_at IS NULL",
    )
    .bind::<Text, _>(&metadata.client_id)
    .bind::<Text, _>(&metadata.client_name)
    .bind::<Nullable<Text>, _>(metadata.client_uri.as_deref())
    .bind::<Nullable<Text>, _>(metadata.logo_uri.as_deref())
    .bind::<Array<Text>, _>(&metadata.redirect_uris)
    .bind::<Array<Text>, _>(&metadata.grant_types)
    .bind::<Array<Text>, _>(metadata.scopes.clone().unwrap_or_default())
    .bind::<Timestamptz, _>(now())
    .execute(conn)
    .await
    .map_err(|e| AuthError::Internal(e.into()))?;
    if changed == 0 {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}

impl Engine {
    /// Whether a CIMD client's row is a revocation tombstone. Lets the
    /// authorize endpoint refuse before any network fetch.
    pub async fn cimd_client_is_revoked(&self, client_id: &str) -> Result<bool, AuthError> {
        let mut conn = self.conn().await?;
        let revoked: Option<Option<chrono::DateTime<Utc>>> = oauth_client::table
            .find(client_id)
            .select(oauth_client::revoked_at)
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AuthError::Internal(e.into()))?;
        Ok(revoked.flatten().is_some())
    }

    /// Deletes CIMD client rows that nothing needs: idle for `ttl` (measured
    /// from the last completed authorization, or creation) and referenced by
    /// no consent, refresh token, authorization code, consent flow or pending
    /// account choice. Revoked rows are tombstones and are kept.
    ///
    /// Candidates are locked `FOR UPDATE SKIP LOCKED`, so a row that a
    /// concurrent consent-flow creation is upserting or referencing is
    /// skipped rather than deleted from under it (the grant tables cascade).
    // `redundant_field_names` is a false positive from `QueryableByName`.
    #[allow(clippy::redundant_field_names)]
    pub async fn gc_unused_cimd_clients(
        &self,
        ttl: std::time::Duration,
    ) -> Result<u64, AuthError> {
        let cutoff = Utc::now()
            - chrono::Duration::from_std(ttl)
                .map_err(|e| AuthError::Internal(anyhow::anyhow!("cimd ttl out of range: {e}")))?;
        let mut conn = self.conn().await?;
        #[derive(QueryableByName)]
        struct Deleted {
            #[diesel(sql_type = BigInt)]
            n: i64,
        }
        let deleted = conn
            .transaction::<_, AuthError, _>(|conn| {
                async move {
                    let rows = diesel::sql_query(
                        "WITH doomed AS ( \
                           SELECT c.client_id FROM surge.oauth_client c \
                            WHERE c.registration_source = 'cimd' \
                              AND c.revoked_at IS NULL \
                              AND COALESCE(c.last_used_at, c.created_at) < $1 \
                              AND NOT EXISTS (SELECT 1 FROM surge.oauth_consent x WHERE x.client_id = c.client_id) \
                              AND NOT EXISTS (SELECT 1 FROM surge.oauth_refresh_token x WHERE x.client_id = c.client_id) \
                              AND NOT EXISTS (SELECT 1 FROM surge.oauth_authorization_code x WHERE x.client_id = c.client_id) \
                              AND NOT EXISTS (SELECT 1 FROM surge.oauth_consent_flow x WHERE x.client_id = c.client_id) \
                              AND NOT EXISTS (SELECT 1 FROM surge.oauth_authorization_request x \
                                               WHERE x.request->>'client_id' = c.client_id) \
                            FOR UPDATE OF c SKIP LOCKED \
                         ), gone AS ( \
                           DELETE FROM surge.oauth_client \
                            WHERE client_id IN (SELECT client_id FROM doomed) \
                           RETURNING 1 \
                         ) SELECT count(*)::bigint AS n FROM gone",
                    )
                    .bind::<Timestamptz, _>(cutoff)
                    .load::<Deleted>(conn)
                    .await
                    .map_err(|e| AuthError::Internal(e.into()))?;
                    Ok(rows.into_iter().next().map_or(0, |r| r.n))
                }
                .scope_boxed()
            })
            .await?;
        Ok(deleted as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "https://app.example/oauth/client.json";

    fn doc(extra: &str) -> Vec<u8> {
        format!(
            r#"{{"client_id":"{ID}","client_name":"App","redirect_uris":["https://app.example/cb","http://127.0.0.1:7000/cb"],"token_endpoint_auth_method":"none"{extra}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn client_id_urls() {
        for ok in [
            ID,
            "https://app.example/a",
            "https://a.b.example/x/y?z=1",
            "https://claude.ai/oauth/claude-code-client-metadata",
        ] {
            assert!(validate_cimd_client_id(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://app.example/c.json",
            "https://app.example",
            "https://app.example/",
            "https://user@app.example/c.json",
            "https://user:pw@app.example/c.json",
            "https://app.example/c.json#frag",
            "https://app.example:8443/c.json",
            "https://app.example:443/c.json",
            "https://127.0.0.1/c.json",
            "https://[::1]/c.json",
            "https://[2606:4700::1]/c.json",
            "https://2130706433/c.json",
            "https://0x7f.1/c.json",
            "https://localhost/c.json",
            "https://intranet/c.json",
            "https://printer.local/c.json",
            "https://svc.internal/c.json",
            "https://APP.example/c.json",
            "https://app.example/a/../c.json",
            "https://app.example/./c.json",
            "ftp://app.example/c.json",
            "file:///etc/passwd",
            "not a url",
            "",
        ] {
            assert!(validate_cimd_client_id(bad).is_err(), "{bad}");
        }
        let long = format!("https://app.example/{}", "a".repeat(2000));
        assert!(validate_cimd_client_id(&long).is_err());
    }

    #[test]
    fn a_valid_document_parses() {
        let m = parse_cimd_document(ID, &doc(r#","scope":"mcp:read mcp:write","grant_types":["authorization_code","refresh_token"]"#))
            .unwrap();
        assert_eq!(m.client_name, "App");
        assert_eq!(m.scopes.as_deref(), Some(&["mcp:read".to_string(), "mcp:write".to_string()][..]));
        assert_eq!(m.publisher_host().as_deref(), Some("app.example"));
        let m = parse_cimd_document(ID, &doc("")).unwrap();
        assert_eq!(m.grant_types, ["authorization_code"]);
        assert_eq!(m.scopes, None);
    }

    #[test]
    fn documents_must_declare_exactly_this_client() {
        let bad = |body: &[u8]| parse_cimd_document(ID, body).is_err();
        assert!(bad(b"[]"));
        assert!(bad(b"not json"));
        assert!(bad(br#"{"client_name":"x"}"#));
        // Another client ID, a trailing slash, a different case.
        for other in [
            "https://app.example/other.json",
            "https://app.example/oauth/client.json/",
            "https://App.example/oauth/client.json",
        ] {
            let body = format!(
                r#"{{"client_id":"{other}","client_name":"App","redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"none"}}"#
            );
            assert!(bad(body.as_bytes()), "{other}");
        }
        let missing = |without: &str| {
            let mut v: serde_json::Value = serde_json::from_slice(&doc("")).unwrap();
            v.as_object_mut().unwrap().remove(without);
            parse_cimd_document(ID, v.to_string().as_bytes()).is_err()
        };
        assert!(missing("client_name"));
        assert!(missing("redirect_uris"));
        assert!(missing("token_endpoint_auth_method"));
        assert!(bad(&doc(r#","client_name":"  ""#)));
    }

    #[test]
    fn only_public_authentication_is_accepted() {
        let with = |m: &str| {
            let mut v: serde_json::Value = serde_json::from_slice(&doc("")).unwrap();
            v["token_endpoint_auth_method"] = m.into();
            parse_cimd_document(ID, v.to_string().as_bytes())
        };
        assert!(with("none").is_ok());
        for m in ["client_secret_basic", "client_secret_post", "private_key_jwt", ""] {
            assert!(with(m).is_err(), "{m}");
        }
        assert!(parse_cimd_document(ID, &doc(r#","client_secret":"s""#)).is_err());
        assert!(parse_cimd_document(ID, &doc(r#","client_secret_expires_at":0"#)).is_err());
    }

    #[test]
    fn redirect_uris_and_other_fields_are_validated() {
        let with = |k: &str, v: serde_json::Value| {
            let mut d: serde_json::Value = serde_json::from_slice(&doc("")).unwrap();
            d[k] = v;
            parse_cimd_document(ID, d.to_string().as_bytes())
        };
        assert!(with("redirect_uris", serde_json::json!(["http://app.example/cb"])).is_err());
        assert!(with("redirect_uris", serde_json::json!(["https://*.app.example/cb"])).is_err());
        assert!(with("redirect_uris", serde_json::json!(["https://app.example/cb#f"])).is_err());
        assert!(with("redirect_uris", serde_json::json!([])).is_err());
        assert!(with("redirect_uris", serde_json::json!("https://app.example/cb")).is_err());
        assert!(with("logo_uri", serde_json::json!("javascript:alert(1)")).is_err());
        assert!(with("client_uri", serde_json::json!(7)).is_err());
        assert!(with("grant_types", serde_json::json!(["implicit"])).is_err());
        assert!(with("grant_types", serde_json::json!(["refresh_token"])).is_err());
        assert!(with("response_types", serde_json::json!(["token"])).is_err());
        assert!(with("response_types", serde_json::json!(["code"])).is_ok());
        assert!(with("client_name", serde_json::json!("x".repeat(500))).is_err());
        let huge = vec![b' '; MAX_CIMD_DOCUMENT_BYTES + 1];
        assert!(parse_cimd_document(ID, &huge).is_err());
    }
}
