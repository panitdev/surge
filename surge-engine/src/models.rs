use chrono::{DateTime, Utc};
use diesel::prelude::*;
use uuid::Uuid;

use crate::schema;

#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::identity)]
pub struct IdentityRow {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::identity)]
pub struct NewIdentity<'a> {
    pub id: Uuid,
    pub username: &'a str,
    pub display_name: &'a str,
    pub avatar_url: Option<&'a str>,
    pub state: &'a str,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::credential_password)]
#[allow(dead_code)]
pub struct CredentialPasswordRow {
    pub identity_id: Uuid,
    pub hash: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::credential_password)]
pub struct NewCredentialPassword<'a> {
    pub identity_id: Uuid,
    pub hash: &'a str,
    pub updated_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::credential_totp)]
#[allow(dead_code)]
pub struct CredentialTotpRow {
    pub identity_id: Uuid,
    pub secret_encrypted: String,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub last_used_step: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::credential_totp)]
pub struct NewCredentialTotp<'a> {
    pub identity_id: Uuid,
    pub secret_encrypted: &'a str,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub last_used_step: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::credential_passphrase)]
#[allow(dead_code)]
pub struct CredentialPassphraseRow {
    pub identity_id: Uuid,
    pub hash: String,
    pub updated_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::credential_passphrase)]
pub struct NewCredentialPassphrase<'a> {
    pub identity_id: Uuid,
    pub hash: &'a str,
    pub updated_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::session)]
#[allow(dead_code)]
pub struct SessionRow {
    pub id: Uuid,
    pub token_hash: Vec<u8>,
    pub identity_id: Uuid,
    pub authenticated_via: serde_json::Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::session)]
pub struct NewSession {
    pub id: Uuid,
    pub token_hash: Vec<u8>,
    pub identity_id: Uuid,
    pub authenticated_via: serde_json::Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::login_flow)]
#[allow(dead_code)]
pub struct LoginFlowRow {
    pub id: String,
    pub return_to: Option<String>,
    pub csrf_token: String,
    pub state: String,
    pub attempts: i32,
    pub error: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub identity_id: Option<Uuid>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::login_flow)]
pub struct NewLoginFlow<'a> {
    pub id: &'a str,
    pub return_to: Option<&'a str>,
    pub csrf_token: &'a str,
    pub state: &'a str,
    pub attempts: i32,
    pub error: Option<&'a str>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::service)]
#[allow(dead_code)]
pub struct ServiceRow {
    pub id: Uuid,
    pub name: String,
    pub token_hash: Vec<u8>,
    pub grants: Vec<String>,
    pub return_origins: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::service)]
pub struct NewService<'a> {
    pub id: Uuid,
    pub name: &'a str,
    pub token_hash: Vec<u8>,
    pub grants: Vec<String>,
    pub return_origins: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::audit_log)]
pub struct NewAuditEntry {
    pub at: DateTime<Utc>,
    pub actor: serde_json::Value,
    pub action: String,
    pub subject: serde_json::Value,
    pub detail: Option<serde_json::Value>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::identity_link)]
pub struct IdentityLinkRow {
    pub provider: String,
    pub subject: String,
    pub identity_id: Uuid,
    pub verified_at: Option<DateTime<Utc>>,
    pub linked_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::identity_link)]
pub struct NewIdentityLink<'a> {
    pub provider: &'a str,
    pub subject: &'a str,
    pub identity_id: Uuid,
    pub verified_at: Option<DateTime<Utc>>,
    pub linked_at: DateTime<Utc>,
}

// -- OAuth authorization server (internal/oauth-as.md §3) --

#[derive(Queryable, Selectable, Clone)]
#[diesel(table_name = schema::oauth_client)]
#[allow(dead_code)]
pub struct OauthClientRow {
    pub client_id: String,
    pub client_secret_hash: Option<Vec<u8>>,
    pub client_name: String,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub registration_source: String,
    pub first_party: bool,
    pub trust_state: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::oauth_client)]
pub struct NewOauthClient<'a> {
    pub client_id: &'a str,
    pub client_secret_hash: Option<Vec<u8>>,
    pub client_name: &'a str,
    pub client_uri: Option<&'a str>,
    pub logo_uri: Option<&'a str>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub token_endpoint_auth_method: &'a str,
    pub registration_source: &'a str,
    pub first_party: bool,
    pub trust_state: &'a str,
    pub created_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable, Clone)]
#[diesel(table_name = schema::oauth_resource)]
pub struct OauthResourceRow {
    pub resource_uri: String,
    pub service_id: Uuid,
    pub scopes: Vec<String>,
    pub scope_descriptions: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::oauth_resource)]
pub struct NewOauthResource<'a> {
    pub resource_uri: &'a str,
    pub service_id: Uuid,
    pub scopes: Vec<String>,
    pub scope_descriptions: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable, Clone)]
#[diesel(table_name = schema::oauth_consent)]
#[allow(dead_code)]
pub struct OauthConsentRow {
    pub client_id: String,
    pub identity_id: Uuid,
    pub resource_uri: String,
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::oauth_consent)]
pub struct NewOauthConsent<'a> {
    pub client_id: &'a str,
    pub identity_id: Uuid,
    pub resource_uri: &'a str,
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable, Clone)]
#[diesel(table_name = schema::oauth_consent_flow)]
#[allow(dead_code)]
pub struct OauthConsentFlowRow {
    pub id: String,
    pub client_id: String,
    pub identity_id: Uuid,
    pub session_id: Uuid,
    pub resource_uri: String,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub csrf_token: String,
    pub decided_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::oauth_consent_flow)]
pub struct NewOauthConsentFlow<'a> {
    pub id: &'a str,
    pub client_id: &'a str,
    pub identity_id: Uuid,
    pub session_id: Uuid,
    pub resource_uri: &'a str,
    pub scopes: Vec<String>,
    pub redirect_uri: &'a str,
    pub state: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub csrf_token: &'a str,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable, Clone)]
#[diesel(table_name = schema::oauth_authorization_code)]
#[allow(dead_code)]
pub struct OauthAuthorizationCodeRow {
    pub code_hash: Vec<u8>,
    pub client_id: String,
    pub identity_id: Uuid,
    pub session_id: Uuid,
    pub resource_uri: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::oauth_authorization_code)]
pub struct NewOauthAuthorizationCode<'a> {
    pub code_hash: Vec<u8>,
    pub client_id: &'a str,
    pub identity_id: Uuid,
    pub session_id: Uuid,
    pub resource_uri: &'a str,
    pub redirect_uri: &'a str,
    pub scopes: Vec<String>,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub nonce: Option<&'a str>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable, Clone)]
#[diesel(table_name = schema::oauth_refresh_token)]
#[allow(dead_code)]
pub struct OauthRefreshTokenRow {
    pub token_hash: Vec<u8>,
    pub client_id: String,
    pub identity_id: Uuid,
    pub session_id: Uuid,
    pub resource_uri: String,
    pub scopes: Vec<String>,
    pub family_id: Uuid,
    pub parent_hash: Option<Vec<u8>>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::oauth_refresh_token)]
pub struct NewOauthRefreshToken<'a> {
    pub token_hash: Vec<u8>,
    pub client_id: &'a str,
    pub identity_id: Uuid,
    pub session_id: Uuid,
    pub resource_uri: &'a str,
    pub scopes: Vec<String>,
    pub family_id: Uuid,
    pub parent_hash: Option<Vec<u8>>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Queryable, Selectable, Clone)]
#[diesel(table_name = schema::oauth_signing_key)]
pub struct OauthSigningKeyRow {
    pub kid: String,
    pub algorithm: String,
    pub private_key_encrypted: String,
    pub public_jwk: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::oauth_signing_key)]
pub struct NewOauthSigningKey<'a> {
    pub kid: &'a str,
    pub algorithm: &'a str,
    pub private_key_encrypted: &'a str,
    pub public_jwk: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
}
