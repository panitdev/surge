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
