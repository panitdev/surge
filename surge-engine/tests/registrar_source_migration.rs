//! Migration 00000000000020: clients created through `oauth_client_register`
//! are recorded as `registrar`, and their constraints follow the new value.
//!
//! Needs a Postgres role that may create databases; the test makes its own
//! scratch database next to the one `DATABASE_URL` names.
//!
//! ```sh
//! DATABASE_URL=postgres://localhost/postgres \
//!   cargo test -p surge-engine --test registrar_source_migration -- --ignored
//! ```

use diesel::connection::SimpleConnection;
use diesel::sql_types::Text;
use diesel::{Connection, PgConnection, QueryableByName, RunQueryDsl};
use diesel_migrations::MigrationHarness;
use surge_engine::MIGRATIONS;
use uuid::Uuid;

const BEFORE: &str = "00000000000019";

const REGISTRAR: &str = "00000000-0000-0000-0000-0000000000a1";
const CLIENT: &str = "aeg_cid_migration_registrar";

#[derive(QueryableByName)]
struct Source {
    #[diesel(sql_type = Text)]
    registration_source: String,
}

fn source(conn: &mut PgConnection) -> String {
    diesel::sql_query(format!(
        "SELECT registration_source FROM surge.oauth_client WHERE client_id = '{CLIENT}'"
    ))
    .get_result::<Source>(conn)
    .unwrap()
    .registration_source
}

fn insert_client(conn: &mut PgConnection, id: &str, source: &str, first_party: bool) -> bool {
    conn.batch_execute(&format!(
        "INSERT INTO surge.oauth_client (client_id, client_name, redirect_uris, scopes, \
             registration_source, registrar_service_id, first_party, scope_ceiling_explicit) \
         VALUES ('{id}', 'Client', ARRAY['https://client.migration.test/cb'], ARRAY['mcp:read'], \
             '{source}', '{REGISTRAR}', {first_party}, true)"
    ))
    .is_ok()
}

fn migrate_to(conn: &mut PgConnection, last: &str) {
    loop {
        let pending = conn.pending_migrations(MIGRATIONS).unwrap();
        let next = pending.first().expect("migration missing");
        let version = next.name().version().to_string();
        conn.run_migration(next).unwrap();
        if version == last {
            return;
        }
    }
}

fn scratch_url(base: &str, name: &str) -> String {
    let mut url = url::Url::parse(base).expect("DATABASE_URL must be a URL");
    url.set_path(&format!("/{name}"));
    url.to_string()
}

#[test]
#[ignore = "requires a Postgres role that can create databases via DATABASE_URL"]
fn registrar_clients_are_renamed_and_constrained() {
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let name = format!("surge_registrar_migration_{}", Uuid::now_v7().simple());
    let mut admin = PgConnection::establish(&base).unwrap();
    diesel::sql_query(format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .unwrap();

    let outcome = std::panic::catch_unwind(|| exercise(&scratch_url(&base, &name)));

    diesel::sql_query(format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn exercise(url: &str) {
    let mut conn = PgConnection::establish(url).unwrap();
    migrate_to(&mut conn, BEFORE);
    assert!(insert_client(&mut conn, CLIENT, "platform", false));

    conn.run_pending_migrations(MIGRATIONS).unwrap();
    assert_eq!(source(&mut conn), "registrar");
    // A well-formed registrar client is accepted, so the refusals below are
    // the constraints at work and not a malformed insert.
    assert!(insert_client(&mut conn, "aeg_cid_new", "registrar", false));
    // The old value is gone, and the registrar invariants hold for the new one.
    assert!(!insert_client(&mut conn, "aeg_cid_old", "platform", false));
    assert!(!insert_client(&mut conn, "aeg_cid_first", "registrar", true));
    assert!(conn
        .batch_execute(
            "INSERT INTO surge.oauth_client (client_id, client_name, redirect_uris, scopes, \
                 registration_source, scope_ceiling_explicit) \
             VALUES ('aeg_cid_orphan', 'Client', ARRAY['https://client.migration.test/cb'], \
                 ARRAY['mcp:read'], 'registrar', true)"
        )
        .is_err());

    // And it reverses cleanly.
    conn.revert_last_migration(MIGRATIONS).unwrap(); // 21, client registrars
    conn.revert_last_migration(MIGRATIONS).unwrap(); // 20, registrar source
    assert_eq!(source(&mut conn), "platform");
}
