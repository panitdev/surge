//! Migration 00000000000012: resource registrations get an immutable identity
//! and every grant is bound to it.
//!
//! Needs a Postgres role that may create databases; the test makes its own
//! scratch database next to the one `DATABASE_URL` names, migrates it to the
//! pre-registration schema, seeds legacy rows, applies the migration and
//! drops the database again.
//!
//! ```sh
//! DATABASE_URL=postgres://localhost/postgres \
//!   cargo test -p surge-engine --test resource_registration_migration -- --ignored
//! ```

#![allow(clippy::redundant_field_names)] // false positive from `QueryableByName`

use std::collections::HashMap;
use std::time::Duration;

use diesel::sql_types::{BigInt, Bool, Nullable, Text, Uuid as SqlUuid};
use diesel::connection::SimpleConnection;
use diesel::{Connection, PgConnection, QueryableByName, RunQueryDsl};
use diesel_migrations::MigrationHarness;
use secrecy::SecretString;
use surge_engine::oauth::{NewOauthClient, RefreshGrant, RegistrationSource, ResourceSource};
use surge_engine::types::IdentityId;
use surge_engine::{AuthError, Engine, EngineConfig, PepperConfig, MIGRATIONS};
use uuid::Uuid;

const LAST_LEGACY: &str = "00000000000011";

const CREATOR: &str = "00000000-0000-0000-0000-0000000000a1";
const OWNER: &str = "00000000-0000-0000-0000-0000000000a2";
const IDENTITY: &str = "00000000-0000-0000-0000-0000000000b1";
const SESSION: &str = "00000000-0000-0000-0000-0000000000c1";
const STALE_FAMILY: &str = "00000000-0000-0000-0000-0000000000f1";
const FRESH_FAMILY: &str = "00000000-0000-0000-0000-0000000000f2";
const KEPT_FAMILY: &str = "00000000-0000-0000-0000-0000000000f3";
const ORPHAN_FAMILY: &str = "00000000-0000-0000-0000-0000000000f4";
const BROWSER: &str = "00000000-0000-0000-0000-0000000000d1";

const KEPT: &str = "https://rs.migration.test/kept";
const REUSED: &str = "https://rs.migration.test/reused";
const GONE: &str = "https://rs.migration.test/gone";
const CLIENT: &str = "aeg_cid_migration_legacy";

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    n: i64,
}

#[derive(QueryableByName)]
struct Registration {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    registration_source: String,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    service_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    registrar_service_id: Option<Uuid>,
    #[diesel(sql_type = BigInt)]
    cimd: i64,
    #[diesel(sql_type = Bool)]
    dcr_enabled: bool,
}

#[derive(QueryableByName)]
struct Bound {
    #[diesel(sql_type = Text)]
    label: String,
    #[diesel(sql_type = SqlUuid)]
    registration_id: Uuid,
}

fn count(conn: &mut PgConnection, sql: &str) -> i64 {
    diesel::sql_query(sql).get_result::<Count>(conn).unwrap().n
}

fn registration(conn: &mut PgConnection, uri: &str) -> Registration {
    diesel::sql_query(format!(
        "SELECT id, registration_source, service_id, registrar_service_id, \
                cardinality(allowed_cimd_client_ids)::BIGINT AS cimd, dcr_enabled \
           FROM surge.oauth_resource WHERE resource_uri = '{uri}'"
    ))
    .get_result(conn)
    .unwrap()
}

fn bound(conn: &mut PgConnection, sql: &str) -> HashMap<String, Uuid> {
    diesel::sql_query(sql)
        .load::<Bound>(conn)
        .unwrap()
        .into_iter()
        .map(|b| (b.label, b.registration_id))
        .collect()
}

fn migrate_to_legacy(conn: &mut PgConnection) {
    loop {
        let pending = conn.pending_migrations(MIGRATIONS).unwrap();
        let next = pending.first().expect("legacy migration missing");
        let version = next.name().version().to_string();
        conn.run_migration(next).unwrap();
        if version == LAST_LEGACY {
            return;
        }
    }
}

/// The world as migration 11 left it: one resource registered for another
/// service, one URI that was deleted and registered again an hour ago, and
/// grants issued against each — plus some for a URI no longer registered.
fn seed_legacy(conn: &mut PgConnection) {
    conn.batch_execute(&format!(
        r#"
        INSERT INTO surge.service (id, name, token_hash, created_at) VALUES
            ('{CREATOR}', 'creator', sha256('creator'::bytea), now()),
            ('{OWNER}', 'owner', sha256('owner'::bytea), now());
        INSERT INTO surge.identity (id, username, display_name, created_at, updated_at)
            VALUES ('{IDENTITY}', 'migration-user', 'Migration User', now(), now());
        INSERT INTO surge.oauth_client (client_id, client_name, redirect_uris)
            VALUES ('{CLIENT}', 'Legacy', ARRAY['https://client.migration.test/cb']);

        -- Registered by CREATOR for OWNER two days ago.
        INSERT INTO surge.oauth_resource (resource_uri, service_id, scopes, created_at)
            VALUES ('{KEPT}', '{OWNER}', ARRAY['mcp:read'], now() - interval '2 days');
        -- Re-registered an hour ago; whoever held it before is not recorded.
        INSERT INTO surge.oauth_resource (resource_uri, service_id, scopes, created_at)
            VALUES ('{REUSED}', '{CREATOR}', ARRAY['mcp:read'], now() - interval '1 hour');

        INSERT INTO surge.oauth_consent (client_id, identity_id, resource_uri, scopes)
            VALUES ('{CLIENT}', '{IDENTITY}', '{KEPT}', ARRAY['mcp:read']);
        "#
    ))
    .unwrap();

    for (id, uri, created) in [
        ("flow-kept", KEPT, "now() - interval '1 minute'"),
        ("flow-stale", REUSED, "now() - interval '2 hours'"),
        ("flow-orphan", GONE, "now() - interval '1 minute'"),
    ] {
        diesel::sql_query(format!(
            "INSERT INTO surge.oauth_consent_flow (id, client_id, identity_id, session_id, \
                 resource_uri, scopes, redirect_uri, code_challenge, code_challenge_method, \
                 csrf_token, expires_at, created_at) \
             VALUES ('{id}', '{CLIENT}', '{IDENTITY}', '{SESSION}', '{uri}', ARRAY['mcp:read'], \
                 'https://client.migration.test/cb', 'challenge', 'S256', 'csrf', \
                 now() + interval '9 minutes', {created})"
        ))
        .execute(conn)
        .unwrap();
    }

    for (label, uri, issued) in [
        ("code-kept", KEPT, "now() - interval '10 seconds'"),
        ("code-stale", REUSED, "now() - interval '2 hours'"),
        ("code-orphan", GONE, "now() - interval '10 seconds'"),
    ] {
        diesel::sql_query(format!(
            "INSERT INTO surge.oauth_authorization_code (code_hash, client_id, identity_id, \
                 session_id, resource_uri, redirect_uri, scopes, code_challenge, \
                 code_challenge_method, nonce, issued_at, expires_at) \
             VALUES (sha256('{label}'::bytea), '{CLIENT}', '{IDENTITY}', '{SESSION}', '{uri}', \
                 'https://client.migration.test/cb', ARRAY['mcp:read'], 'challenge', 'S256', \
                 '{label}', {issued}, now() + interval '50 seconds')"
        ))
        .execute(conn)
        .unwrap();
    }

    // The stale family was born before the re-registration and rotated after
    // it; its first token is what decides.
    for (label, family, uri, issued, consumed) in [
        ("stale-root", STALE_FAMILY, REUSED, "now() - interval '3 hours'", "now()"),
        ("stale-child", STALE_FAMILY, REUSED, "now() - interval '30 minutes'", "NULL"),
        ("fresh", FRESH_FAMILY, REUSED, "now() - interval '10 minutes'", "NULL"),
        ("kept", KEPT_FAMILY, KEPT, "now() - interval '1 day'", "NULL"),
        ("orphan", ORPHAN_FAMILY, GONE, "now() - interval '1 minute'", "NULL"),
    ] {
        diesel::sql_query(format!(
            "INSERT INTO surge.oauth_refresh_token (token_hash, client_id, identity_id, \
                 session_id, resource_uri, scopes, family_id, issued_at, expires_at, consumed_at) \
             VALUES (sha256('{label}'::bytea), '{CLIENT}', '{IDENTITY}', '{SESSION}', '{uri}', \
                 ARRAY['mcp:read'], '{family}', {issued}, now() + interval '30 days', {consumed})"
        ))
        .execute(conn)
        .unwrap();
    }

    diesel::sql_query(format!(
        "INSERT INTO surge.browser_session (id, token_hash) VALUES ('{BROWSER}', sha256('b'::bytea))"
    ))
    .execute(conn)
    .unwrap();
    for (id, uri, expires) in [
        ("request-kept", KEPT, "now() + interval '9 minutes'"),
        ("request-stale", REUSED, "now() - interval '55 minutes'"),
        ("request-orphan", GONE, "now() + interval '9 minutes'"),
    ] {
        diesel::sql_query(format!(
            "INSERT INTO surge.oauth_authorization_request (id, browser_id, request, expires_at) \
             VALUES ('{id}', '{BROWSER}', jsonb_build_object('resource', '{uri}'), {expires})"
        ))
        .execute(conn)
        .unwrap();
    }
}

fn scratch_url(base: &str, name: &str) -> String {
    let mut url = url::Url::parse(base).expect("DATABASE_URL must be a URL");
    url.set_path(&format!("/{name}"));
    url.to_string()
}

#[tokio::test]
#[ignore = "requires a Postgres role that can create databases via DATABASE_URL"]
async fn legacy_resources_become_registrations_with_bound_grants() {
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let name = format!("surge_registration_migration_{}", Uuid::now_v7().simple());
    let mut admin = PgConnection::establish(&base).unwrap();
    diesel::sql_query(format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .unwrap();
    let url = scratch_url(&base, &name);

    let outcome = tokio::spawn(exercise(url)).await;

    diesel::sql_query(format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .unwrap();
    outcome.unwrap();
}

async fn exercise(url: String) {
    let mut conn = PgConnection::establish(&url).unwrap();
    migrate_to_legacy(&mut conn);
    seed_legacy(&mut conn);
    conn.run_pending_migrations(MIGRATIONS).unwrap();

    let owner: Uuid = OWNER.parse().unwrap();
    let creator: Uuid = CREATOR.parse().unwrap();
    let identity = IdentityId::from_uuid(IDENTITY.parse().unwrap());

    // Service registrations with their assigned owner; nothing invented.
    let kept = registration(&mut conn, KEPT);
    assert_eq!(kept.registration_source, "service");
    assert_eq!(kept.service_id, Some(owner));
    assert_eq!(kept.registrar_service_id, None, "an unknown registrar stays unknown");
    assert_eq!(kept.cimd, 0);
    assert!(!kept.dcr_enabled);
    let reused = registration(&mut conn, REUSED);
    assert_eq!(reused.service_id, Some(creator));
    assert_ne!(kept.id, reused.id);

    assert_eq!(
        count(
            &mut conn,
            &format!(
                "SELECT count(*) AS n FROM surge.oauth_client \
                  WHERE client_id = '{CLIENT}' AND NOT audience_restricted"
            )
        ),
        1,
        "legacy clients carry no explicit audience list"
    );

    // Grants that can be attributed are bound; the rest are gone.
    let consents = bound(
        &mut conn,
        "SELECT resource_uri AS label, registration_id FROM surge.oauth_consent",
    );
    assert_eq!(consents, HashMap::from([(KEPT.to_string(), kept.id)]));
    let flows = bound(
        &mut conn,
        "SELECT id AS label, registration_id FROM surge.oauth_consent_flow",
    );
    assert_eq!(flows, HashMap::from([("flow-kept".to_string(), kept.id)]));
    let codes = bound(
        &mut conn,
        "SELECT nonce AS label, registration_id FROM surge.oauth_authorization_code",
    );
    assert_eq!(codes, HashMap::from([("code-kept".to_string(), kept.id)]));
    let families = bound(
        &mut conn,
        "SELECT family_id::TEXT AS label, registration_id FROM surge.oauth_refresh_token",
    );
    assert_eq!(
        families,
        HashMap::from([
            (FRESH_FAMILY.to_string(), reused.id),
            (KEPT_FAMILY.to_string(), kept.id),
        ])
    );
    let requests = bound(
        &mut conn,
        "SELECT id AS label, registration_id FROM surge.oauth_authorization_request",
    );
    assert_eq!(requests, HashMap::from([("request-kept".to_string(), kept.id)]));

    assert!(
        diesel::sql_query(format!(
            "UPDATE surge.oauth_resource SET resource_uri = '{GONE}' WHERE id = '{}'",
            kept.id
        ))
        .execute(&mut conn)
        .is_err(),
        "a registration's URI is part of its identity"
    );

    let engine = Engine::new(EngineConfig {
        database_url: SecretString::from(url.clone()),
        pepper: PepperConfig {
            current_version: 1,
            peppers: HashMap::from([(1, SecretString::from("migration-pepper".to_string()))]),
        },
        session_ttl: Duration::from_secs(3600),
    })
    .await
    .unwrap();

    // Introspection authority follows the assigned owner.
    let owned: Vec<_> = engine
        .oauth_resources_for_service(owner)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.registration_id)
        .collect();
    assert_eq!(owned, vec![kept.id]);
    let resource = engine.get_oauth_resource(KEPT).await.unwrap();
    assert_eq!(resource.registration_source, ResourceSource::Service);
    assert!(engine.get_oauth_client(CLIENT).await.unwrap().audiences.is_none());
    assert!(engine.oauth_grant_is_live(CLIENT, identity, kept.id).await.unwrap());
    assert!(engine.oauth_grant_is_live(CLIENT, identity, reused.id).await.unwrap());

    // Re-registering a URI never restores what the previous registration had.
    let (restricted, _) = engine
        .create_oauth_client(NewOauthClient {
            client_name: "Restricted".into(),
            client_uri: None,
            logo_uri: None,
            redirect_uris: vec!["https://client.migration.test/cb".into()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            scopes: vec!["mcp:read".into()],
            confidential: false,
            first_party: false,
            registration_source: RegistrationSource::Admin,
            audiences: Some(vec![format!("{KEPT}/")]),
        })
        .await
        .unwrap();
    assert_eq!(restricted.audiences, Some(vec![KEPT.to_string()]));
    assert!(matches!(
        engine
            .create_oauth_client(NewOauthClient {
                client_name: "Unknown audience".into(),
                client_uri: None,
                logo_uri: None,
                redirect_uris: vec!["https://client.migration.test/cb".into()],
                grant_types: vec!["authorization_code".into()],
                scopes: vec![],
                confidential: false,
                first_party: false,
                registration_source: RegistrationSource::Admin,
                audiences: Some(vec![GONE.to_string()]),
            })
            .await,
        Err(AuthError::Validation(_))
    ));

    // The reservation is lapsed by hand: this test is about what survives
    // re-registering.
    engine
        .delete_oauth_resource(
            surge_engine::audit::AuditActor::Operator { name: "test".into() },
            surge_engine::oauth::ResourceManager::Admin,
            KEPT,
            None,
            Some(Duration::ZERO),
        )
        .await
        .unwrap();
    diesel::sql_query("UPDATE surge.oauth_resource_reservation SET reserved_until = now() - interval '1 second'")
        .execute(&mut conn)
        .unwrap();
    let replacement = engine
        .create_oauth_resource(KEPT, creator, vec!["mcp:read".into()], serde_json::json!({}))
        .await
        .unwrap();
    assert_ne!(replacement.registration_id, kept.id);
    assert!(engine.get_oauth_registration(kept.id).await.is_err());
    assert_eq!(
        engine.get_oauth_client(&restricted.client_id).await.unwrap().audiences,
        Some(vec![])
    );
    assert!(engine
        .find_consent(CLIENT, identity, replacement.registration_id)
        .await
        .unwrap()
        .is_none());
    assert!(!engine
        .oauth_grant_is_live(CLIENT, identity, replacement.registration_id)
        .await
        .unwrap());
    for table in [
        "oauth_consent",
        "oauth_consent_flow",
        "oauth_authorization_code",
        "oauth_refresh_token",
        "oauth_authorization_request",
    ] {
        let sql = format!(
            "SELECT count(*) AS n FROM surge.{table} WHERE registration_id = '{}'",
            kept.id
        );
        assert_eq!(count(&mut conn, &sql), 0, "{table} outlived its registration");
    }

    // A grant decided against the old registration cannot continue under
    // the new one.
    let stale = RefreshGrant {
        client_id: CLIENT.into(),
        identity_id: identity,
        session_id: SESSION.parse().unwrap(),
        registration_id: kept.id,
        resource_uri: KEPT.into(),
        scopes: vec!["mcp:read".into()],
        family_id: Uuid::now_v7(),
    };
    assert!(matches!(
        engine
            .issue_refresh_token(&stale, Duration::from_secs(60))
            .await,
        Err(AuthError::InvalidToken)
    ));
    let current = RefreshGrant {
        registration_id: replacement.registration_id,
        ..stale
    };
    engine
        .issue_refresh_token(&current, Duration::from_secs(60))
        .await
        .unwrap();
    drop(engine);

    // And the migration reverses cleanly.
    conn.revert_last_migration(MIGRATIONS).unwrap(); // 14, resource lifecycle
    conn.revert_last_migration(MIGRATIONS).unwrap(); // 13, client registrar
    conn.revert_last_migration(MIGRATIONS).unwrap();
    assert_eq!(
        count(
            &mut conn,
            "SELECT count(*) AS n FROM information_schema.columns \
              WHERE table_schema = 'surge' AND column_name = 'registration_id'"
        ),
        0
    );
    conn.run_pending_migrations(MIGRATIONS).unwrap();
}
