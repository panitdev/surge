//! Changing and ending a registration after it exists.
//!
//! # Serialization
//!
//! Policy (scopes, the CIMD allowlist, DCR opt-in, existence) and the grants
//! issued under it must never interleave in a way that leaves a live grant
//! the new policy forbids. One lock decides it, on the `oauth_resource` row:
//!
//! * **Policy changes** (`PATCH`, `DELETE`) take `FOR UPDATE` on the row,
//!   apply the change, and invalidate affected grants, all in one
//!   transaction.
//! * **Every write that creates or extends a grant** — creating a consent
//!   flow, minting a code (with its consent), issuing the first refresh token
//!   of a grant, rotating a refresh token — takes `FOR SHARE` on the same row
//!   *first*, re-evaluates eligibility and scopes against what it locked
//!   ([`admit`]), and writes in that same transaction.
//!
//! `FOR SHARE` conflicts with `FOR UPDATE`, so each issuance either commits
//! before the policy change begins — and the change then sees and invalidates
//! what it wrote — or starts after it commits and is judged by the new
//! policy. There is no third case. Shared locks do not conflict, so issuance
//! does not serialize against itself.
//!
//! A steady stream of overlapping issuance can in principle keep a policy
//! change waiting: Postgres queues the `FOR UPDATE` behind shared holders
//! already granted, but a long-running issuance transaction delays it for as
//! long as it runs. Issuance transactions are short (no network I/O is done
//! while holding the lock), so the wait is bounded by their duration.
//!
//! **Lock order** is registration row first, then anything else (flow, code
//! and token rows, session rows). A transaction that took a grant row first
//! and then asked for the registration would deadlock against a policy change
//! holding the registration and reaching for the grant row.
//!
//! Policy changes never touch client rows, so the client's own state
//! (audience list, revocation) is read under the registration lock but is not
//! serialized by it; those changes have their own invalidation
//! (`revoke_oauth_client`) and the eligibility rule re-reads them at every
//! stage.
//!
//! # Invalidation
//!
//! Introspection answers from grant liveness (`oauth_grant_is_live`), not
//! from eligibility, so every invalidation here ends the *refresh families* —
//! that is what makes an already-issued access token introspect inactive.
//! Consents, pending flows, unredeemed codes and pending account choices are
//! deleted, so regaining eligibility requires a fresh authorization.
//!
//! # Reuse
//!
//! Deleting a registration reserves its URI for [`reuse_window`] of the
//! longest access-token lifetime ever configured: access tokens already
//! issued verify offline until they expire. Every access token's `exp` is
//! fixed from a time before its grant-creating transaction commits, so no
//! token outlives a reservation that began after that commit.

use std::collections::BTreeSet;
use std::time::Duration;

use chrono::Utc;
use diesel::prelude::*;
use diesel::sql_types::{Array, Text, Uuid as SqlUuid};
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

use super::resource::{canonicalize_resource_uri, row_to_resource};
use super::{client_may_use_resource, OauthResource, ResourceSource};
use crate::audit::{audit_conn, AuditActor};
use crate::models::{OauthClientRow, OauthResourceRow};
use crate::schema::{
    oauth_authorization_code, oauth_client, oauth_consent, oauth_consent_flow, oauth_refresh_token,
    oauth_resource, oauth_resource_reservation,
};
use crate::types::*;
use crate::Engine;

/// Clock skew resource servers are assumed to accept on `exp`
/// (`jsonwebtoken`'s default leeway, which Surge's own verifiers use).
pub const ACCESS_TOKEN_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// How long a deleted registration's URI stays reserved: the longest an
/// access token issued for it can still verify.
pub fn reuse_window(max_access_ttl: Duration) -> Duration {
    max_access_ttl + ACCESS_TOKEN_CLOCK_SKEW
}

/// Most scopes, CIMD allowlist entries and so on one registration may carry.
const MAX_LIST_LEN: usize = 100;
const MAX_ENTRY_LEN: usize = 2000;

/// Scopes that ask for identity claims rather than naming a resource scope.
/// They never appear in a registration's scope list.
pub(crate) const PSEUDO_SCOPES: [&str; 3] = ["openid", "profile", "offline_access"];

/// Who is managing a registration. Mirrors the service API's authority:
/// administration reaches every registration, a registrar only the delegated
/// ones it created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceManager {
    Admin,
    Registrar(Uuid),
}

impl ResourceManager {
    pub fn can_manage(self, resource: &OauthResource) -> bool {
        self.can_manage_parts(resource.registration_source, resource.registrar_service_id)
    }

    fn can_manage_parts(self, source: ResourceSource, registrar: Option<Uuid>) -> bool {
        match self {
            Self::Admin => true,
            Self::Registrar(id) => source == ResourceSource::Delegated && registrar == Some(id),
        }
    }
}

/// The fields a registration's owner may change. `None` leaves a field alone.
#[derive(Debug, Default, Clone)]
pub struct ResourcePatch {
    pub scopes: Option<Vec<String>>,
    pub scope_descriptions: Option<serde_json::Value>,
    pub allowed_cimd_client_ids: Option<Vec<String>>,
    pub dcr_enabled: Option<bool>,
}

/// What a delete did.
#[derive(Debug)]
pub enum DeleteOutcome {
    Deleted(OauthResource),
    /// The named registration was already deleted: a retry, which touched
    /// nothing.
    AlreadyDeleted,
}

/// What a policy change ended, for the audit trail.
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
struct Invalidated {
    refresh_tokens_revoked: u64,
    consents_removed: u64,
    consents_trimmed: u64,
    flows_removed: u64,
    codes_removed: u64,
    requests_removed: u64,
}

fn field(field: &'static str, message: impl Into<String>) -> AuthError {
    AuthError::Validation(ValidationError::Field {
        field,
        message: message.into(),
    })
}

fn not_found(e: diesel::result::Error) -> AuthError {
    match e {
        diesel::result::Error::NotFound => AuthError::NotFound,
        other => AuthError::Internal(other.into()),
    }
}

fn internal(e: diesel::result::Error) -> AuthError {
    AuthError::Internal(e.into())
}

/// Takes the shared lock a grant-creating write must hold, and checks that
/// `client_id` may use the registration and that `scopes` are still among its
/// scopes, against the state it just locked.
///
/// `NotFound`: the registration is gone. `Forbidden`: the client may no
/// longer use it. `ScopeNotGranted`: it no longer offers a scope.
pub(crate) async fn admit(
    conn: &mut AsyncPgConnection,
    client_id: &str,
    registration_id: Uuid,
    scopes: &[String],
) -> Result<OauthResource, AuthError> {
    let resource = lock_registration_shared(conn, registration_id).await?;
    let client_row: Option<OauthClientRow> = oauth_client::table
        .find(client_id)
        .filter(oauth_client::revoked_at.is_null())
        .select(OauthClientRow::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(internal)?;
    let Some(client_row) = client_row else {
        return Err(AuthError::Forbidden);
    };
    let client = super::client::rows_to_clients(conn, vec![client_row])
        .await?
        .remove(0);
    if !client_may_use_resource(&client, &resource) {
        return Err(AuthError::Forbidden);
    }
    let offered = |s: &String| {
        PSEUDO_SCOPES.contains(&s.as_str()) || resource.scopes.iter().any(|r| r == s)
    };
    if !scopes.iter().all(offered) {
        return Err(AuthError::ScopeNotGranted);
    }
    Ok(resource)
}

/// `FOR SHARE` on a registration: see the module docs.
pub(crate) async fn lock_registration_shared(
    conn: &mut AsyncPgConnection,
    registration_id: Uuid,
) -> Result<OauthResource, AuthError> {
    let row: OauthResourceRow = oauth_resource::table
        .find(registration_id)
        .select(OauthResourceRow::as_select())
        .for_share()
        .first(conn)
        .await
        .map_err(not_found)?;
    Ok(row_to_resource(row))
}

fn valid_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 128
        && scope.chars().all(|c| c.is_ascii_graphic() && c != '"' && c != '\\')
}

fn validate_scopes(scopes: Vec<String>) -> Result<Vec<String>, AuthError> {
    if scopes.is_empty() {
        return Err(field("scopes", "a resource must offer at least one scope"));
    }
    if scopes.len() > MAX_LIST_LEN {
        return Err(field("scopes", format!("at most {MAX_LIST_LEN} scopes are allowed")));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(scopes.len());
    for scope in scopes {
        if !valid_scope_token(&scope) {
            return Err(field(
                "scopes",
                "a scope is a non-empty run of printable characters with no spaces",
            ));
        }
        if PSEUDO_SCOPES.contains(&scope.as_str()) {
            return Err(field(
                "scopes",
                format!("`{scope}` is an identity scope, not a resource scope"),
            ));
        }
        if seen.insert(scope.clone()) {
            out.push(scope);
        }
    }
    Ok(out)
}

fn validate_descriptions(value: &serde_json::Value) -> Result<(), AuthError> {
    let Some(map) = value.as_object() else {
        return Err(field(
            "scope_descriptions",
            "must be a JSON object of {scope: description}",
        ));
    };
    if map.len() > MAX_LIST_LEN
        || map
            .values()
            .any(|v| v.as_str().is_none_or(|s| s.len() > MAX_ENTRY_LEN))
    {
        return Err(field(
            "scope_descriptions",
            "descriptions must be strings of bounded length",
        ));
    }
    Ok(())
}

/// A CIMD client ID is the HTTPS URL of its metadata document. The entry is
/// matched exactly, so it is stored exactly as given; it only has to be a URL
/// that could be one.
fn validate_cimd_ids(ids: Vec<String>) -> Result<Vec<String>, AuthError> {
    if ids.len() > MAX_LIST_LEN {
        return Err(field(
            "allowed_cimd_client_ids",
            format!("at most {MAX_LIST_LEN} entries are allowed"),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let bad = |why: &str| field("allowed_cimd_client_ids", format!("`{id}`: {why}"));
        if id.len() > MAX_ENTRY_LEN {
            return Err(bad("too long"));
        }
        let url = url::Url::parse(&id).map_err(|_| bad("not a URL"))?;
        if url.scheme() != "https" || !id.starts_with("https://") {
            return Err(bad("must be an https URL"));
        }
        if url.path().len() <= 1 {
            return Err(bad("must have a path"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(bad("must not carry userinfo"));
        }
        if url.fragment().is_some() {
            return Err(bad("must not carry a fragment"));
        }
        if seen.insert(id.clone()) {
            out.push(id);
        }
    }
    Ok(out)
}

fn resource_subject(resource: &OauthResource) -> serde_json::Value {
    serde_json::json!({
        "registration_id": resource.registration_id,
        "resource_uri": resource.resource_uri,
        "registration_source": resource.registration_source,
        "owner_service_id": resource.service_id,
        "registrar_service_id": resource.registrar_service_id,
    })
}

/// `FOR UPDATE` on the registration holding `canonical`, if any.
async fn lock_registration_exclusive(
    conn: &mut AsyncPgConnection,
    canonical: &str,
) -> Result<Option<OauthResource>, AuthError> {
    let row: Option<OauthResourceRow> = oauth_resource::table
        .filter(oauth_resource::resource_uri.eq(canonical))
        .select(OauthResourceRow::as_select())
        .for_update()
        .first(conn)
        .await
        .optional()
        .map_err(internal)?;
    Ok(row.map(row_to_resource))
}

impl Engine {
    /// Changes a registration's scopes, descriptions, CIMD allowlist or DCR
    /// opt-in, ending the grants the new policy no longer permits (see the
    /// module docs). `if_registration`, when given, must name the
    /// registration currently holding the URI.
    ///
    /// Not-yours and missing look alike (`NotFound`). A patch that changes
    /// nothing writes nothing and is not audited.
    pub async fn update_oauth_resource(
        &self,
        actor: AuditActor,
        manager: ResourceManager,
        resource_uri: &str,
        if_registration: Option<Uuid>,
        patch: ResourcePatch,
    ) -> Result<OauthResource, AuthError> {
        let canonical = canonicalize_resource_uri(resource_uri)?;
        if patch.scopes.is_none()
            && patch.scope_descriptions.is_none()
            && patch.allowed_cimd_client_ids.is_none()
            && patch.dcr_enabled.is_none()
        {
            return Err(field(
                "body",
                "provide at least one of scopes, scope_descriptions, allowed_cimd_client_ids, dcr_enabled",
            ));
        }
        let scopes = patch.scopes.map(validate_scopes).transpose()?;
        if let Some(d) = &patch.scope_descriptions {
            validate_descriptions(d)?;
        }
        let cimd = patch
            .allowed_cimd_client_ids
            .map(validate_cimd_ids)
            .transpose()?;
        let dcr = patch.dcr_enabled;
        let descriptions = patch.scope_descriptions;

        let mut conn = self.conn().await?;
        conn.transaction::<_, AuthError, _>(|conn| {
            async move {
                let old = lock_registration_exclusive(conn, &canonical)
                    .await?
                    .filter(|r| manager.can_manage(r))
                    .ok_or(AuthError::NotFound)?;
                if if_registration.is_some_and(|id| id != old.registration_id) {
                    return Err(AuthError::PreconditionFailed);
                }
                if dcr.is_some_and(|d| d != old.dcr_enabled)
                    && old.registration_source != ResourceSource::Delegated
                {
                    return Err(field(
                        "dcr_enabled",
                        "dynamic registration opt-in applies to delegated registrations only",
                    ));
                }

                let new_scopes = scopes.unwrap_or_else(|| old.scopes.clone());
                let new_cimd = cimd.unwrap_or_else(|| old.allowed_cimd_client_ids.clone());
                let new_dcr = dcr.unwrap_or(old.dcr_enabled);
                if let Some(map) = descriptions.as_ref().and_then(|d| d.as_object())
                    && let Some(stray) = map.keys().find(|k| !new_scopes.contains(k))
                {
                    return Err(field(
                        "scope_descriptions",
                        format!("`{stray}` is not one of the resource's scopes"),
                    ));
                }
                let mut new_descriptions =
                    descriptions.unwrap_or_else(|| old.scope_descriptions.clone());

                let removed_scopes: Vec<String> = old
                    .scopes
                    .iter()
                    .filter(|s| !new_scopes.contains(s))
                    .cloned()
                    .collect();
                // A description for a scope that no longer exists would be
                // rendered for nothing and resurrected if it returned.
                if let Some(map) = new_descriptions.as_object_mut() {
                    map.retain(|scope, _| !removed_scopes.contains(scope));
                }
                let removed_cimd: Vec<String> = old
                    .allowed_cimd_client_ids
                    .iter()
                    .filter(|id| !new_cimd.contains(id))
                    .cloned()
                    .collect();
                let added_cimd: Vec<String> = new_cimd
                    .iter()
                    .filter(|id| !old.allowed_cimd_client_ids.contains(id))
                    .cloned()
                    .collect();

                if new_scopes == old.scopes
                    && new_cimd == old.allowed_cimd_client_ids
                    && new_dcr == old.dcr_enabled
                    && new_descriptions == old.scope_descriptions
                {
                    return Ok(old);
                }

                let row: OauthResourceRow = diesel::update(oauth_resource::table.find(old.registration_id))
                    .set((
                        oauth_resource::scopes.eq(&new_scopes),
                        oauth_resource::scope_descriptions.eq(&new_descriptions),
                        oauth_resource::allowed_cimd_client_ids.eq(&new_cimd),
                        oauth_resource::dcr_enabled.eq(new_dcr),
                    ))
                    .returning(OauthResourceRow::as_returning())
                    .get_result(conn)
                    .await
                    .map_err(internal)?;
                let updated = row_to_resource(row);

                let mut ended = Invalidated::default();
                if !removed_scopes.is_empty() {
                    ended.add(trim_removed_scopes(conn, updated.registration_id, &removed_scopes).await?);
                }
                if !removed_cimd.is_empty() || (old.dcr_enabled && !new_dcr) {
                    ended.add(
                        end_ineligible_grants(conn, &updated, &removed_cimd).await?,
                    );
                }

                audit_conn(
                    conn,
                    actor,
                    "update_oauth_resource",
                    resource_subject(&updated),
                    Some(serde_json::json!({
                        "scopes_removed": removed_scopes,
                        "scopes_added": new_scopes.iter().filter(|s| !old.scopes.contains(s)).collect::<Vec<_>>(),
                        "scope_descriptions_changed": new_descriptions != old.scope_descriptions,
                        "cimd_client_ids_removed": removed_cimd,
                        "cimd_client_ids_added": added_cimd,
                        "dcr_enabled": { "from": old.dcr_enabled, "to": new_dcr },
                        "invalidated": ended,
                    })),
                )
                .await?;
                Ok(updated)
            }
            .scope_boxed()
        })
        .await
    }

    /// Deletes a registration and, in the same transaction, ends every grant
    /// bound to it and reserves its URI for `reuse_window` (see
    /// [`reuse_window`]).
    ///
    /// The reservation lasts [`reuse_window`] of the longer of
    /// `configured_access_ttl` (this process's setting, if it has one) and
    /// the persisted high-water mark of every lifetime ever configured. If
    /// neither is known the delete is refused: no safe window can be named.
    ///
    /// `if_registration` is the registration the caller means to delete. With
    /// it, a retry can never delete a successor registered at the same URI:
    /// if that id was already deleted the call is `AlreadyDeleted`; if the URI
    /// now holds a different registration, `PreconditionFailed`. Without it
    /// the call deletes whatever holds the URI.
    pub async fn delete_oauth_resource(
        &self,
        actor: AuditActor,
        manager: ResourceManager,
        resource_uri: &str,
        if_registration: Option<Uuid>,
        configured_access_ttl: Option<Duration>,
    ) -> Result<DeleteOutcome, AuthError> {
        let canonical = canonicalize_resource_uri(resource_uri)?;

        let mut conn = self.conn().await?;
        conn.transaction::<_, AuthError, _>(|conn| {
            async move {
                let current = lock_registration_exclusive(conn, &canonical)
                    .await?
                    .filter(|r| manager.can_manage(r));

                let Some(resource) = current else {
                    if let Some(id) = if_registration
                        && already_deleted(conn, manager, &canonical, id).await?
                    {
                        return Ok(DeleteOutcome::AlreadyDeleted);
                    }
                    return Err(AuthError::NotFound);
                };
                if let Some(id) = if_registration
                    && id != resource.registration_id
                {
                    if already_deleted(conn, manager, &canonical, id).await? {
                        return Ok(DeleteOutcome::AlreadyDeleted);
                    }
                    return Err(AuthError::PreconditionFailed);
                }

                let window = {
                    let recorded = access_ttl_high_water(conn).await?;
                    let ttl = [configured_access_ttl, recorded].into_iter().flatten().max();
                    let ttl = ttl.ok_or_else(|| {
                        field(
                            "access_ttl",
                            "no access-token lifetime is recorded for this deployment; start the \
                             server once with SURGE_OAUTH_ISSUER set (or run this with the same \
                             environment) so a safe reservation window is known",
                        )
                    })?;
                    chrono::Duration::from_std(reuse_window(ttl)).map_err(|e| {
                        AuthError::Internal(anyhow::anyhow!("reuse window out of range: {e}"))
                    })?
                };
                let ended = count_live_grants(conn, resource.registration_id).await?;
                let deleted_at = Utc::now();
                diesel::insert_into(oauth_resource_reservation::table)
                    .values((
                        oauth_resource_reservation::resource_uri.eq(&resource.resource_uri),
                        oauth_resource_reservation::registration_id.eq(resource.registration_id),
                        oauth_resource_reservation::registration_source
                            .eq(resource.registration_source.as_str()),
                        oauth_resource_reservation::service_id.eq(resource.service_id),
                        oauth_resource_reservation::registrar_service_id
                            .eq(resource.registrar_service_id),
                        oauth_resource_reservation::deleted_at.eq(deleted_at),
                        oauth_resource_reservation::reserved_until.eq(deleted_at + window),
                    ))
                    // A leftover from an earlier deletion that has expired.
                    .on_conflict(oauth_resource_reservation::resource_uri)
                    .do_update()
                    .set((
                        oauth_resource_reservation::registration_id.eq(resource.registration_id),
                        oauth_resource_reservation::registration_source
                            .eq(resource.registration_source.as_str()),
                        oauth_resource_reservation::service_id.eq(resource.service_id),
                        oauth_resource_reservation::registrar_service_id
                            .eq(resource.registrar_service_id),
                        oauth_resource_reservation::deleted_at.eq(deleted_at),
                        oauth_resource_reservation::reserved_until.eq(deleted_at + window),
                    ))
                    .execute(conn)
                    .await
                    .map_err(internal)?;

                // The foreign keys carry consents, flows, codes, refresh
                // tokens, pending choices and client approvals away with it.
                diesel::delete(oauth_resource::table.find(resource.registration_id))
                    .execute(conn)
                    .await
                    .map_err(internal)?;

                audit_conn(
                    conn,
                    actor,
                    "delete_oauth_resource",
                    resource_subject(&resource),
                    Some(serde_json::json!({
                        "reserved_until": deleted_at + window,
                        "ended": ended,
                    })),
                )
                .await?;
                Ok(DeleteOutcome::Deleted(resource))
            }
            .scope_boxed()
        })
        .await
    }

    /// Records that access tokens may be issued with a lifetime of
    /// `access_ttl`. Raises the persisted high-water mark if it is higher
    /// than any before; never lowers it.
    pub async fn raise_access_ttl_high_water(&self, access_ttl: Duration) -> Result<(), AuthError> {
        use crate::schema::oauth_access_ttl_high_water as hw;
        let secs = access_ttl.as_secs().max(1) as i64;
        let mut conn = self.conn().await?;
        diesel::insert_into(hw::table)
            .values(hw::max_access_ttl_secs.eq(secs))
            .on_conflict(hw::singleton)
            .do_update()
            .set(hw::max_access_ttl_secs.eq(diesel::dsl::sql::<diesel::sql_types::BigInt>(
                "GREATEST(oauth_access_ttl_high_water.max_access_ttl_secs, excluded.max_access_ttl_secs)",
            )))
            .execute(&mut conn)
            .await
            .map_err(internal)?;
        Ok(())
    }

    /// The longest access-token lifetime ever configured, if any is recorded.
    pub async fn access_ttl_high_water(&self) -> Result<Option<Duration>, AuthError> {
        let mut conn = self.conn().await?;
        access_ttl_high_water(&mut conn).await
    }

    /// Drops reservations whose window ended long enough ago that no retry
    /// can still want them. A reservation stops blocking registration the
    /// moment it expires; this only reclaims the rows.
    pub async fn gc_expired_resource_reservations(&self) -> Result<u64, AuthError> {
        let mut conn = self.conn().await?;
        let cutoff = Utc::now() - chrono::Duration::days(7);
        let deleted = diesel::delete(
            oauth_resource_reservation::table
                .filter(oauth_resource_reservation::reserved_until.lt(cutoff)),
        )
        .execute(&mut conn)
        .await
        .map_err(internal)?;
        Ok(deleted as u64)
    }
}

impl Invalidated {
    fn add(&mut self, other: Invalidated) {
        self.refresh_tokens_revoked += other.refresh_tokens_revoked;
        self.consents_removed += other.consents_removed;
        self.consents_trimmed += other.consents_trimmed;
        self.flows_removed += other.flows_removed;
        self.codes_removed += other.codes_removed;
        self.requests_removed += other.requests_removed;
    }
}

#[derive(Debug, serde::Serialize)]
struct LiveGrants {
    live_refresh_tokens: i64,
    consents: i64,
}

async fn count_live_grants(
    conn: &mut AsyncPgConnection,
    registration_id: Uuid,
) -> Result<LiveGrants, AuthError> {
    Ok(LiveGrants {
        live_refresh_tokens: oauth_refresh_token::table
            .filter(oauth_refresh_token::registration_id.eq(registration_id))
            .filter(oauth_refresh_token::revoked_at.is_null())
            .count()
            .get_result(conn)
            .await
            .map_err(internal)?,
        consents: oauth_consent::table
            .filter(oauth_consent::registration_id.eq(registration_id))
            .count()
            .get_result(conn)
            .await
            .map_err(internal)?,
    })
}

/// Scope removal: ends the refresh families that carry a removed scope,
/// trims consents (deleting those left empty), and drops unredeemed codes and
/// pending flows that would grant one. Grants that never carried a removed
/// scope are untouched.
#[allow(clippy::field_reassign_with_default)]
async fn trim_removed_scopes(
    conn: &mut AsyncPgConnection,
    registration_id: Uuid,
    removed: &[String],
) -> Result<Invalidated, AuthError> {
    let mut ended = Invalidated::default();
    let at = Utc::now();

    // A family is revoked whole, including the token that carries no removed
    // scope of its own: rotation carries the grant's scope set forward.
    let families: Vec<Uuid> = oauth_refresh_token::table
        .filter(oauth_refresh_token::registration_id.eq(registration_id))
        .filter(oauth_refresh_token::scopes.overlaps_with(removed))
        .select(oauth_refresh_token::family_id)
        .distinct()
        .load(conn)
        .await
        .map_err(internal)?;
    ended.refresh_tokens_revoked = diesel::update(
        oauth_refresh_token::table
            .filter(oauth_refresh_token::family_id.eq_any(families))
            .filter(oauth_refresh_token::revoked_at.is_null()),
    )
    .set(oauth_refresh_token::revoked_at.eq(at))
    .execute(conn)
    .await
    .map_err(internal)? as u64;

    ended.consents_trimmed = diesel::sql_query(
        "UPDATE surge.oauth_consent \
            SET scopes = ARRAY(SELECT s FROM unnest(scopes) WITH ORDINALITY AS t(s, n) \
                               WHERE s <> ALL($2) ORDER BY n) \
          WHERE registration_id = $1 AND scopes && $2",
    )
    .bind::<SqlUuid, _>(registration_id)
    .bind::<Array<Text>, _>(removed)
    .execute(conn)
    .await
    .map_err(internal)? as u64;
    ended.consents_removed = diesel::delete(
        oauth_consent::table
            .filter(oauth_consent::registration_id.eq(registration_id))
            .filter(diesel::dsl::sql::<diesel::sql_types::Bool>(
                "cardinality(scopes) = 0",
            )),
    )
    .execute(conn)
    .await
    .map_err(internal)? as u64;
    // Counted above as trimmed; they were removed instead.
    ended.consents_trimmed = ended.consents_trimmed.saturating_sub(ended.consents_removed);

    ended.flows_removed = diesel::delete(
        oauth_consent_flow::table
            .filter(oauth_consent_flow::registration_id.eq(registration_id))
            .filter(oauth_consent_flow::scopes.overlaps_with(removed)),
    )
    .execute(conn)
    .await
    .map_err(internal)? as u64;
    ended.codes_removed = diesel::delete(
        oauth_authorization_code::table
            .filter(oauth_authorization_code::registration_id.eq(registration_id))
            .filter(oauth_authorization_code::scopes.overlaps_with(removed)),
    )
    .execute(conn)
    .await
    .map_err(internal)? as u64;
    Ok(ended)
}

/// Eligibility narrowed (a CIMD client left the allowlist, or DCR was turned
/// off): ends every grant, flow, code and pending choice of each client that
/// the registration's new policy no longer admits.
///
/// `removed_cimd` are the client IDs just taken off the allowlist. They are
/// ended by name rather than evaluated, which also covers a grant whose CIMD
/// row was removed since (surge-bcc stores one per client once a consent flow
/// exists). Every other client holding anything at the registration
/// is evaluated with the shared rule against the new policy.
// `redundant_field_names` is a false positive from `QueryableByName`.
#[allow(clippy::field_reassign_with_default, clippy::redundant_field_names)]
async fn end_ineligible_grants(
    conn: &mut AsyncPgConnection,
    resource: &OauthResource,
    removed_cimd: &[String],
) -> Result<Invalidated, AuthError> {
    let id = resource.registration_id;

    let mut candidates: BTreeSet<String> = BTreeSet::new();
    candidates.extend(
        oauth_refresh_token::table
            .filter(oauth_refresh_token::registration_id.eq(id))
            .select(oauth_refresh_token::client_id)
            .distinct()
            .load::<String>(conn)
            .await
            .map_err(internal)?,
    );
    candidates.extend(
        oauth_consent::table
            .filter(oauth_consent::registration_id.eq(id))
            .select(oauth_consent::client_id)
            .distinct()
            .load::<String>(conn)
            .await
            .map_err(internal)?,
    );
    candidates.extend(
        oauth_consent_flow::table
            .filter(oauth_consent_flow::registration_id.eq(id))
            .select(oauth_consent_flow::client_id)
            .distinct()
            .load::<String>(conn)
            .await
            .map_err(internal)?,
    );
    candidates.extend(
        oauth_authorization_code::table
            .filter(oauth_authorization_code::registration_id.eq(id))
            .select(oauth_authorization_code::client_id)
            .distinct()
            .load::<String>(conn)
            .await
            .map_err(internal)?,
    );
    #[derive(QueryableByName)]
    struct Pending {
        #[diesel(sql_type = Text)]
        client_id: String,
    }
    candidates.extend(
        diesel::sql_query(
            "SELECT DISTINCT request->>'client_id' AS client_id \
               FROM surge.oauth_authorization_request \
              WHERE registration_id = $1 AND request->>'client_id' IS NOT NULL",
        )
        .bind::<SqlUuid, _>(id)
        .load::<Pending>(conn)
        .await
        .map_err(internal)?
        .into_iter()
        .map(|p| p.client_id),
    );

    let mut to_end: Vec<String> = candidates
        .iter()
        .filter(|c| removed_cimd.contains(c))
        .cloned()
        .collect();
    let rest: Vec<&String> = candidates.iter().filter(|c| !removed_cimd.contains(c)).collect();
    if !rest.is_empty() {
        let rows: Vec<OauthClientRow> = oauth_client::table
            .filter(oauth_client::client_id.eq_any(&rest))
            .select(OauthClientRow::as_select())
            .load(conn)
            .await
            .map_err(internal)?;
        let found: BTreeSet<String> = rows.iter().map(|r| r.client_id.clone()).collect();
        // A grant whose client has no row cannot be evaluated, so it is not
        // trusted.
        to_end.extend(rest.iter().filter(|c| !found.contains(**c)).map(|c| (*c).clone()));
        for client in super::client::rows_to_clients(conn, rows).await? {
            // A revoked client's refresh tokens were already ended; ending
            // the rest of its state here is harmless and tidy.
            if !client_may_use_resource(&client, resource) {
                to_end.push(client.client_id);
            }
        }
    }
    // Clients named by the allowlist that held nothing still need no work,
    // but one that holds something under a CIMD ID outside `candidates`
    // cannot exist.
    if to_end.is_empty() {
        return Ok(Invalidated::default());
    }

    let at = Utc::now();
    let mut ended = Invalidated::default();
    ended.refresh_tokens_revoked = diesel::update(
        oauth_refresh_token::table
            .filter(oauth_refresh_token::registration_id.eq(id))
            .filter(oauth_refresh_token::client_id.eq_any(&to_end))
            .filter(oauth_refresh_token::revoked_at.is_null()),
    )
    .set(oauth_refresh_token::revoked_at.eq(at))
    .execute(conn)
    .await
    .map_err(internal)? as u64;
    ended.consents_removed = diesel::delete(
        oauth_consent::table
            .filter(oauth_consent::registration_id.eq(id))
            .filter(oauth_consent::client_id.eq_any(&to_end)),
    )
    .execute(conn)
    .await
    .map_err(internal)? as u64;
    ended.flows_removed = diesel::delete(
        oauth_consent_flow::table
            .filter(oauth_consent_flow::registration_id.eq(id))
            .filter(oauth_consent_flow::client_id.eq_any(&to_end)),
    )
    .execute(conn)
    .await
    .map_err(internal)? as u64;
    ended.codes_removed = diesel::delete(
        oauth_authorization_code::table
            .filter(oauth_authorization_code::registration_id.eq(id))
            .filter(oauth_authorization_code::client_id.eq_any(&to_end)),
    )
    .execute(conn)
    .await
    .map_err(internal)? as u64;
    ended.requests_removed = diesel::sql_query(
        "DELETE FROM surge.oauth_authorization_request \
          WHERE registration_id = $1 AND request->>'client_id' = ANY($2)",
    )
    .bind::<SqlUuid, _>(id)
    .bind::<Array<Text>, _>(&to_end)
    .execute(conn)
    .await
    .map_err(internal)? as u64;
    Ok(ended)
}

async fn access_ttl_high_water(conn: &mut AsyncPgConnection) -> Result<Option<Duration>, AuthError> {
    use crate::schema::oauth_access_ttl_high_water as hw;
    let secs: Option<i64> = hw::table
        .select(hw::max_access_ttl_secs)
        .first(conn)
        .await
        .optional()
        .map_err(internal)?;
    Ok(secs.map(|s| Duration::from_secs(s.max(0) as u64)))
}

/// Whether `id` is a registration this manager could manage that was deleted
/// from `canonical` and is still remembered: a retried delete.
async fn already_deleted(
    conn: &mut AsyncPgConnection,
    manager: ResourceManager,
    canonical: &str,
    id: Uuid,
) -> Result<bool, AuthError> {
    let row: Option<(String, Option<Uuid>)> = oauth_resource_reservation::table
        .filter(oauth_resource_reservation::registration_id.eq(id))
        .filter(oauth_resource_reservation::resource_uri.eq(canonical))
        .select((
            oauth_resource_reservation::registration_source,
            oauth_resource_reservation::registrar_service_id,
        ))
        .first(conn)
        .await
        .optional()
        .map_err(internal)?;
    Ok(row.is_some_and(|(source, registrar)| {
        manager.can_manage_parts(ResourceSource::from_db(&source), registrar)
    }))
}

/// Used by creation: refuses a URI whose reservation is still running, and
/// clears one that has lapsed. Called *after* the registration row is
/// inserted, inside the same transaction: the insert waits for any
/// concurrent delete of the URI to commit, so the reservation that delete
/// leaves behind is visible to this check.
pub(super) async fn check_reservation(
    conn: &mut AsyncPgConnection,
    canonical: &str,
) -> Result<(), AuthError> {
    let until: Option<chrono::DateTime<Utc>> = oauth_resource_reservation::table
        .find(canonical)
        .select(oauth_resource_reservation::reserved_until)
        .for_update()
        .first(conn)
        .await
        .optional()
        .map_err(internal)?;
    match until {
        Some(until) if until > Utc::now() => Err(AuthError::ResourceReserved(until)),
        Some(_) => {
            diesel::delete(oauth_resource_reservation::table.find(canonical))
                .execute(conn)
                .await
                .map_err(internal)?;
            Ok(())
        }
        None => Ok(()),
    }
}
