//! Identity links: the one way an external provider attaches to an identity.
//!
//! There is deliberately no "register through a provider" path parallel to
//! [`Engine::create_identity_and_session`]. Registration through a provider is
//! identity-creation *composed with* a link, and composing it here — inside
//! one transaction — is what makes [`Engine::authenticate_by_link`] safe to
//! call from an OAuth callback, which never knows in advance whether it is
//! looking at a signup or a returning user.

use chrono::Utc;
use diesel::prelude::*;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

use crate::identity::insert_identity;
use crate::models::{IdentityLinkRow, NewIdentityLink};
use crate::schema::identity_link;
use crate::session::mint_session_conn;
use crate::types::*;
use crate::Engine;

impl Engine {
    /// Resolve `(provider, subject)` to a session, creating the identity on
    /// first sight. This is the whole external-auth entry point.
    ///
    /// **Only a verified link authenticates.** An unverified row is a pending
    /// claim — someone typed an address into account settings and nobody has
    /// proven control of it yet — so it resolves to `NotFound` here rather
    /// than to a session. Surge cannot itself verify an external account; the
    /// caller asserts proof of control by holding the grant that reaches this
    /// method, and links minted through it are verified by construction.
    ///
    /// Concurrency: two callbacks for the same new subject can both miss the
    /// lookup. One wins the primary key and the other takes the conflict
    /// branch, re-resolves, and returns the same identity — so a double-click
    /// through an OAuth callback produces one identity, not two or an error.
    pub async fn authenticate_by_link(
        &self,
        provider: &str,
        subject: &str,
        seed: &LinkSeed,
    ) -> Result<LinkAuth, AuthError> {
        if let Some(identity) = self.resolve_verified_link(provider, subject).await? {
            let issued = self.mint_for(identity).await?;
            return Ok(LinkAuth::new(issued, false));
        }

        match self.create_identity_with_link(provider, subject, seed).await {
            Ok(issued) => Ok(LinkAuth::new(issued, true)),
            // Lost the race for this subject. Note the arm is keyed on the
            // link's own field: `insert_identity` reports a username clash as
            // `UsernameTaken`, which must surface to the caller (they need to
            // pick another username) rather than trigger a re-resolve that
            // would find nothing and report a misleading `NotFound`.
            Err(AuthError::Validation(ValidationError::Field {
                field: LINK_CONFLICT_FIELD,
                ..
            })) => {
                let identity = self
                    .resolve_verified_link(provider, subject)
                    .await?
                    .ok_or(AuthError::NotFound)?;
                let issued = self.mint_for(identity).await?;
                Ok(LinkAuth::new(issued, false))
            }
            Err(other) => Err(other),
        }
    }

    /// Attach a link to an existing identity, or confirm one already attached
    /// to it.
    ///
    /// Re-attaching the same `(provider, subject)` to the same identity is
    /// idempotent and refreshes `verified_at`, which is how a pending email
    /// claim becomes a usable one once its confirmation token comes back.
    /// Attaching a subject already linked to a *different* identity fails:
    /// silently moving it would hand the second identity a login for the
    /// first.
    pub async fn link_identity(
        &self,
        identity_id: IdentityId,
        provider: &str,
        subject: &str,
        verified: bool,
    ) -> Result<IdentityLink, AuthError> {
        let mut conn = self.conn().await?;

        match insert_link(&mut conn, identity_id, provider, subject, verified).await {
            // Someone inserted this subject between our read and our insert.
            // Nothing here runs in a transaction, so the failed statement
            // poisoned nothing: re-running lets the read branch decide whether
            // this is an idempotent confirm or a genuine conflict.
            Err(AuthError::Validation(ValidationError::Field {
                field: LINK_CONFLICT_FIELD,
                ..
            })) => insert_link(&mut conn, identity_id, provider, subject, verified).await,
            other => other,
        }
    }

    /// Every link on an identity — "which accounts are connected to mine?".
    pub async fn identity_links(
        &self,
        identity_id: IdentityId,
    ) -> Result<Vec<IdentityLink>, AuthError> {
        let mut conn = self.conn().await?;

        let rows: Vec<IdentityLinkRow> = identity_link::table
            .filter(identity_link::identity_id.eq(*identity_id.as_uuid()))
            .order(identity_link::linked_at.asc())
            .select(IdentityLinkRow::as_select())
            .load(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(rows.into_iter().map(row_to_link).collect())
    }

    /// Detach a link. Scoped to `identity_id` on purpose: the primary key
    /// alone would let a caller detach someone else's link, and unlinking is
    /// a routine enough action ("disconnect Google") that the check belongs
    /// here rather than in every call site.
    pub async fn unlink_identity(
        &self,
        identity_id: IdentityId,
        provider: &str,
        subject: &str,
    ) -> Result<(), AuthError> {
        let mut conn = self.conn().await?;

        let affected = diesel::delete(
            identity_link::table
                .find((provider, subject))
                .filter(identity_link::identity_id.eq(*identity_id.as_uuid())),
        )
        .execute(&mut conn)
        .await
        .map_err(|e| AuthError::Internal(e.into()))?;

        if affected == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    /// The identity behind a *verified* link, or `None`. Unverified links are
    /// invisible here by design — see [`Engine::authenticate_by_link`].
    ///
    /// This is also the lookup a recovery flow wants: resolve
    /// `("email", address)` to the identity that proved control of it, then
    /// issue whatever reset the caller implements.
    pub async fn resolve_verified_link(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<Identity>, AuthError> {
        let mut conn = self.conn().await?;

        let row: Option<IdentityLinkRow> = identity_link::table
            .find((provider, subject))
            .filter(identity_link::verified_at.is_not_null())
            .select(IdentityLinkRow::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| AuthError::Internal(e.into()))?;

        let Some(row) = row else {
            return Ok(None);
        };

        self.get_identity(IdentityId::from_uuid(row.identity_id))
            .await
            .map(Some)
    }

    /// Identity + link + session, or none of them.
    async fn create_identity_with_link(
        &self,
        provider: &str,
        subject: &str,
        seed: &LinkSeed,
    ) -> Result<IssuedSession, AuthError> {
        let ttl = self.session_ttl;
        let mut conn = self.conn().await?;

        conn.transaction::<_, AuthError, _>(|conn| {
            async move {
                let identity = insert_identity(conn, &seed.username, &seed.display_name).await?;
                insert_link(conn, identity.id, provider, subject, true).await?;
                mint_session_conn(conn, identity, AuthMethod::External, ttl).await
            }
            .scope_boxed()
        })
        .await
    }

    async fn mint_for(&self, identity: Identity) -> Result<IssuedSession, AuthError> {
        if identity.state == IdentityState::Disabled {
            return Err(AuthError::IdentityDisabled);
        }
        self.mint_session(identity.id, AuthMethod::External).await
    }
}

/// The `field` an already-linked-elsewhere conflict reports under. Matched on
/// in `authenticate_by_link` to tell a lost race apart from a username clash.
pub(crate) const LINK_CONFLICT_FIELD: &str = "identity_link";

/// Attach or confirm, scoped to the owner.
///
/// The existing row is read *before* the insert rather than through
/// `ON CONFLICT`, because this runs inside `create_identity_with_link`'s
/// transaction: a unique violation aborts a Postgres transaction, and any
/// query issued afterwards to inspect the conflict would fail too. Reading
/// first keeps the conflict branch query-free, so the error can propagate out
/// of the transaction intact.
///
/// That leaves the narrow window where two callers both read nothing and both
/// insert. One takes the unique violation and is reported as a conflict, which
/// is exactly what the callers above want: `authenticate_by_link` re-resolves
/// the winner's link, and `link_identity` re-runs this function so the read
/// branch can decide idempotent-confirm versus genuine conflict.
pub(crate) async fn insert_link(
    conn: &mut AsyncPgConnection,
    identity_id: IdentityId,
    provider: &str,
    subject: &str,
    verified: bool,
) -> Result<IdentityLink, AuthError> {
    let now = Utc::now();
    let verified_at = verified.then_some(now);

    let existing: Option<IdentityLinkRow> = identity_link::table
        .find((provider, subject))
        .select(IdentityLinkRow::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| AuthError::Internal(e.into()))?;

    if let Some(row) = existing {
        // Re-linking a subject already bound elsewhere would hand this
        // identity a login for that one.
        if row.identity_id != *identity_id.as_uuid() {
            return Err(link_conflict());
        }

        let updated: IdentityLinkRow = diesel::update(identity_link::table.find((provider, subject)))
            .set(identity_link::verified_at.eq(verified_at))
            .returning(IdentityLinkRow::as_returning())
            .get_result(conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        return Ok(row_to_link(updated));
    }

    let new = NewIdentityLink {
        provider,
        subject,
        identity_id: *identity_id.as_uuid(),
        verified_at,
        linked_at: now,
    };

    diesel::insert_into(identity_link::table)
        .values(&new)
        .execute(conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => link_conflict(),
            // The only foreign key on this table is identity_id -> identity(id),
            // so a violation means the identity being linked to is not there.
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::ForeignKeyViolation,
                _,
            ) => AuthError::NotFound,
            other => AuthError::Internal(other.into()),
        })?;

    Ok(IdentityLink::new(
        provider.to_string(),
        subject.to_string(),
        identity_id,
        verified_at,
        now,
    ))
}

fn link_conflict() -> AuthError {
    AuthError::Validation(ValidationError::Field {
        field: LINK_CONFLICT_FIELD,
        message: "already linked".into(),
    })
}

fn row_to_link(row: IdentityLinkRow) -> IdentityLink {
    IdentityLink::new(
        row.provider,
        row.subject,
        IdentityId::from_uuid(row.identity_id),
        row.verified_at,
        row.linked_at,
    )
}
