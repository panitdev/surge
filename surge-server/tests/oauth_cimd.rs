//! Client-ID metadata document (CIMD) clients end to end: advertisement,
//! allowlist gating, metadata validation, the shared client row, tombstones,
//! cleanup, and redemption without a network fetch.
//!
//! Documents are served by an injected in-memory fetcher; nothing here
//! reaches the network. The fetcher's own SSRF defences are unit-tested in
//! `surge::router::oauth_as::cimd`.

mod oauth_support;

use std::time::Duration;

use axum::http::StatusCode;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use oauth_support::*;
use serde_json::{Value, json};
use surge_engine::oauth::{CimdMetadata, ConsentFlowRequest};
use surge_engine::schema::oauth_client;
use tower::ServiceExt;
use uuid::Uuid;

async fn db() -> AsyncPgConnection {
    AsyncPgConnection::establish(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap()
}

fn cimd_url(h: &Harness, name: &str) -> String {
    format!("https://{name}.cimd.test/client-{}.json", h.suffix)
}

async fn call(
    h: &Harness,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> axum::response::Response {
    let req = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            body.map(|b| b.to_string()).unwrap_or_default(),
        ))
        .unwrap();
    h.app.clone().oneshot(req).await.unwrap()
}

async fn open(h: &Harness) {
    let resp = call(
        h,
        "PATCH",
        &format!("/v1/oauth/resources/{}", percent_encode(&h.resource_uri)),
        &h.service_token,
        Some(json!({ "cimd_open": true })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["cimd_open"], true);
    assert_eq!(body["allowed_cimd_client_ids"], json!([]));
}

/// Allows exactly `ids` on the harness's service resource.
async fn allow(h: &Harness, ids: &[&str]) {
    let resp = call(
        h,
        "PATCH",
        &format!("/v1/oauth/resources/{}", percent_encode(&h.resource_uri)),
        &h.service_token,
        Some(json!({ "allowed_cimd_client_ids": ids })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

struct Row {
    name: String,
    source: String,
    first_party: bool,
    trust: String,
    auth_method: String,
    secret: bool,
    revoked: bool,
    redirects: Vec<String>,
}

async fn row(id: &str) -> Option<Row> {
    type Columns = (String, String, bool, String, String, bool, bool, Vec<String>);
    let found: Option<Columns> =
        oauth_client::table
            .find(id)
            .select((
                oauth_client::client_name,
                oauth_client::registration_source,
                oauth_client::first_party,
                oauth_client::trust_state,
                oauth_client::token_endpoint_auth_method,
                oauth_client::client_secret_hash.is_not_null(),
                oauth_client::revoked_at.is_not_null(),
                oauth_client::redirect_uris,
            ))
            .first(&mut db().await)
            .await
            .optional()
            .unwrap();
    found.map(|(name, source, first_party, trust, auth_method, secret, revoked, redirects)| Row {
        name,
        source,
        first_party,
        trust,
        auth_method,
        secret,
        revoked,
        redirects,
    })
}

async fn authorize(h: &Harness, id: &str, session: Option<&str>) -> axum::response::Response {
    let pkce = Pkce::generate();
    h.get(
        &h.authorize_uri(id, &pkce, Some(&h.resource_uri), Some("mcp:read")),
        session,
    )
    .await
}

/// Authorize -> approve -> code, returning the code and PKCE pair.
async fn code_for(h: &Harness, id: &str, session: &str) -> (String, Pkce) {
    let pkce = Pkce::generate();
    let resp = h
        .get(
            &h.authorize_uri(id, &pkce, Some(&h.resource_uri), Some("mcp:read")),
            Some(session),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let mut target = location(&resp);
    if let Some(flow) = query_param(&target, "consent_flow") {
        let csrf = body_json(h.get(&format!("/v1/oauth/consent/{flow}"), Some(session)).await)
            .await["csrf_token"]
            .as_str()
            .unwrap()
            .to_string();
        let resp = h
            .post_json(
                &format!("/v1/oauth/consent/{flow}"),
                json!({ "approve": true, "csrf_token": csrf }),
                Some(session),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        target = body_json(resp).await["redirect_to"].as_str().unwrap().to_string();
    }
    (query_param(&target, "code").unwrap_or_else(|| panic!("no code: {target}")), pkce)
}

async fn redeem(h: &Harness, id: &str, code: &str, pkce: &Pkce) -> (StatusCode, Value) {
    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", CLIENT_REDIRECT),
                ("client_id", id),
                ("code_verifier", &pkce.verifier),
            ],
        )
        .await;
    (resp.status(), body_json(resp).await)
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn metadata_advertises_cimd_support() {
    let h = harness().await;
    let resp = h.get("/.well-known/oauth-authorization-server", None).await;
    assert_eq!(body_json(resp).await["client_id_metadata_document_supported"], true);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn an_unlisted_open_client_gets_consent_with_its_publisher_hostname() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    let session = h.sign_in().await;
    let id = cimd_url(&h, "ok");
    docs.publish(
        &id,
        json!({
            "client_id": id,
            "client_name": "Trusted Account Administrator",
            "redirect_uris": [CLIENT_REDIRECT],
            "token_endpoint_auth_method": "none",
        }),
    );
    open(&h).await;
    assert!(row(&id).await.is_none());

    let resp = authorize(&h, &id, Some(&session)).await;
    let flow = query_param(&location(&resp), "consent_flow").expect("consent flow");

    let r = row(&id).await.expect("row is created with the consent flow");
    assert_eq!(r.source, "cimd");
    assert_eq!(r.name, "Trusted Account Administrator");
    assert!(!r.first_party);
    assert_eq!(r.trust, "untrusted");
    assert_eq!(r.auth_method, "none");
    assert!(!r.secret);
    assert_eq!(r.redirects, vec![CLIENT_REDIRECT.to_string()]);

    let view = body_json(h.get(&format!("/v1/oauth/consent/{flow}"), Some(&session)).await).await;
    assert_eq!(view["client"]["client_id"], id);
    assert_eq!(view["client"]["dynamically_registered"], true);
    assert_eq!(view["client"]["first_party"], false);
    assert_eq!(view["client"]["client_name"], "Trusted Account Administrator");
    assert_eq!(view["client"]["publisher_host"], "ok.cimd.test");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn only_an_exactly_allowed_url_is_fetched() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    let session = h.sign_in().await;
    let listed = cimd_url(&h, "listed");
    let unlisted = cimd_url(&h, "unlisted");
    docs.publish_default(&listed);
    docs.publish_default(&unlisted);
    allow(&h, &[&listed]).await;

    for id in [
        unlisted.clone(),
        format!("{listed}/"),
        listed.replace("https://", "https://x."),
    ] {
        let resp = authorize(&h, &id, Some(&session)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{id}");
        assert!(row(&id).await.is_none(), "{id}");
    }
    assert_eq!(docs.fetches(), 0, "nothing outside the allowlist is fetched");

}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn delegated_resources_require_an_exact_entry_too() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    let session = h.sign_in().await;
    let token = surge_engine::types::ServiceToken::generate();
    h.engine
        .create_service(
            &format!("cimd-registrar-{}", h.suffix),
            token.hash(),
            vec!["oauth_resource_register".to_string()],
            vec![],
        )
        .await
        .unwrap();
    let token = token.expose_secret().to_string();
    let rs = format!("https://delegated.cimd.test/mcp-{}", h.suffix);
    let resp = call(
        &h,
        "POST",
        "/v1/oauth/resources",
        &token,
        Some(json!({ "resource_uri": rs, "scopes": ["mcp:read"] })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let id = cimd_url(&h, "deleg");
    docs.publish_default(&id);

    let go = || async {
        h.get(
            &h.authorize_uri(&id, &Pkce::generate(), Some(&rs), Some("mcp:read")),
            Some(&session),
        )
        .await
    };
    // Not listed: refused without a fetch, whatever DCR or bindings say.
    assert_eq!(go().await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(docs.fetches(), 0);

    // The same client can use a different service resource whose policy is open.
    open(&h).await;
    assert!(
        query_param(
            &location(&authorize(&h, &id, Some(&session)).await),
            "consent_flow"
        )
        .is_some()
    );
    assert_eq!(go().await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(docs.fetches(), 1);

    let resp = call(
        &h,
        "PATCH",
        &format!("/v1/oauth/resources/{}", percent_encode(&rs)),
        &token,
        Some(json!({ "allowed_cimd_client_ids": [id] })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(query_param(&location(&go().await), "consent_flow").is_some());
    assert_eq!(row(&id).await.unwrap().source, "cimd");
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn open_resources_share_the_outbound_fetch_budget() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    open(&h).await;
    let other = format!("https://other.cimd.test/mcp-{}", h.suffix);
    let created = call(
        &h,
        "POST",
        "/v1/oauth/resources",
        &h.service_token,
        Some(json!({
            "resource_uri": other,
            "scopes": ["mcp:read"],
            "cimd_open": true,
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);

    let limit = surge::router::CimdLimits::default().outbound_burst;
    let pkce = Pkce::generate();
    for i in 0..limit {
        let id = cimd_url(&h, &format!("budget{i}"));
        docs.publish_default(&id);
        let audience = if i % 2 == 0 { &h.resource_uri } else { &other };
        let response = h
            .get(
                &h.authorize_uri(&id, &pkce, Some(audience), Some("mcp:read")),
                None,
            )
            .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }
    let extra = cimd_url(&h, "over-budget");
    docs.publish_default(&extra);
    let response = h
        .get(
            &h.authorize_uri(&extra, &pkce, Some(&other), Some("mcp:read")),
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body_text(response)
            .await
            .contains("temporarily_unavailable")
    );

    // Reuse metadata fetched for the first audience on the second audience.
    let cached = cimd_url(&h, "budget0");
    let response = h
        .get(
            &h.authorize_uri(&cached, &pkce, Some(&other), Some("mcp:read")),
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(docs.fetches(), limit);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn documents_that_do_not_validate_are_refused_and_leave_no_row() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    let session = h.sign_in().await;

    type Mutation = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Mutation)> = vec![
        ("mismatch", Box::new(|d| d["client_id"] = "https://evil.test/x.json".into())),
        ("noname", Box::new(|d| { d.as_object_mut().unwrap().remove("client_name"); })),
        ("noredirects", Box::new(|d| d["redirect_uris"] = json!([]))),
        ("badredirect", Box::new(|d| d["redirect_uris"] = json!(["http://evil.test/cb"]))),
        ("noauth", Box::new(|d| { d.as_object_mut().unwrap().remove("token_endpoint_auth_method"); })),
        ("basic", Box::new(|d| d["token_endpoint_auth_method"] = "client_secret_basic".into())),
        ("secret", Box::new(|d| d["client_secret"] = "s3cret".into())),
    ];
    let mut ids = vec![];
    for (name, mutate) in &cases {
        let id = cimd_url(&h, name);
        let mut doc = CimdDocs::default_doc(&id);
        mutate(&mut doc);
        docs.publish(&id, doc);
        ids.push(id);
    }
    // And one that is not published at all.
    ids.push(cimd_url(&h, "missing"));
    open(&h).await;

    for id in &ids {
        let resp = authorize(&h, id, Some(&session)).await;
        assert!(
            resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::SERVICE_UNAVAILABLE,
            "{id}: {}",
            resp.status()
        );
        assert!(resp.headers().get("location").is_none(), "{id}");
        assert!(row(id).await.is_none(), "{id}");
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn the_redirect_uri_must_be_one_the_document_declares_and_pkce_is_required() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    let session = h.sign_in().await;
    let id = cimd_url(&h, "redir");
    docs.publish_default(&id);
    allow(&h, &[&id]).await;

    let pkce = Pkce::generate();
    let uri = h
        .authorize_uri(&id, &pkce, Some(&h.resource_uri), Some("mcp:read"))
        .replace(
            &percent_encode(CLIENT_REDIRECT),
            &percent_encode("https://client.oauth.test/elsewhere"),
        );
    let resp = h.get(&uri, Some(&session)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get("location").is_none());

    // PKCE: absent, or the plain method.
    let base = h.authorize_uri(&id, &pkce, Some(&h.resource_uri), Some("mcp:read"));
    let no_pkce = base.replace(&format!("&code_challenge={}", pkce.challenge), "");
    let resp = h.get(&no_pkce, Some(&session)).await;
    assert_eq!(query_param(&location(&resp), "error").as_deref(), Some("invalid_request"));
    let plain = base.replace("code_challenge_method=S256", "code_challenge_method=plain");
    let resp = h.get(&plain, Some(&session)).await;
    assert_eq!(query_param(&location(&resp), "error").as_deref(), Some("invalid_request"));
    assert!(row(&id).await.is_none());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_row_is_written_only_after_the_session_and_scope_checks_pass() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    let session = h.sign_in().await;
    let id = cimd_url(&h, "late");
    docs.publish_default(&id);
    allow(&h, &[&id]).await;

    // No session: sent to log in, nothing stored.
    let resp = authorize(&h, &id, None).await;
    assert!(location(&resp).contains("/v1/login"));
    assert!(row(&id).await.is_none());

    // A scope the resource does not offer.
    let resp = h
        .get(
            &h.authorize_uri(&id, &Pkce::generate(), Some(&h.resource_uri), Some("nope")),
            Some(&session),
        )
        .await;
    assert_eq!(query_param(&location(&resp), "error").as_deref(), Some("invalid_scope"));
    assert!(row(&id).await.is_none());

    // prompt=none cannot reach the consent step either.
    let uri = h.authorize_uri(&id, &Pkce::generate(), Some(&h.resource_uri), Some("mcp:read"));
    let resp = h.get(&format!("{uri}&prompt=none"), Some(&session)).await;
    assert_eq!(query_param(&location(&resp), "error").as_deref(), Some("consent_required"));
    assert!(row(&id).await.is_none());

    let resp = authorize(&h, &id, Some(&session)).await;
    assert!(query_param(&location(&resp), "consent_flow").is_some());
    assert!(row(&id).await.is_some());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn concurrent_requests_converge_on_one_row() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    let session = h.sign_in().await;
    let id = cimd_url(&h, "race");
    docs.publish_default(&id);
    allow(&h, &[&id]).await;

    let results = futures_util::future::join_all((0..12).map(|_| authorize(&h, &id, Some(&session)))).await;
    for resp in &results {
        assert!(query_param(&location(resp), "consent_flow").is_some());
    }
    let n: i64 = oauth_client::table
        .filter(oauth_client::client_id.eq(&id))
        .count()
        .get_result(&mut db().await)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn redemption_and_refresh_use_the_stored_binding_without_fetching() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    let session = h.sign_in().await;
    let id = cimd_url(&h, "redeem");
    docs.publish_default(&id);
    open(&h).await;

    let (code, pkce) = code_for(&h, &id, &session).await;
    let fetched = docs.fetches();
    assert!(fetched >= 1);
    // The document disappears; nothing past authorization may need it.
    docs.unpublish(&id);

    let (status, tokens) = redeem(&h, &id, &code, &pkce).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let refresh = tokens["refresh_token"].as_str().expect("refresh token").to_string();
    let resp = h
        .post_form(
            "/oauth2/token",
            &[("grant_type", "refresh_token"), ("refresh_token", &refresh), ("client_id", &id)],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(docs.fetches(), fetched, "no fetch at the token endpoint");

    // A secret presented for a public CIMD client is refused, not ignored.
    let resp = h
        .post_form(
            "/oauth2/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &id),
                ("client_secret", "guess"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn a_revoked_row_stays_a_tombstone() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    let session = h.sign_in().await;
    let id = cimd_url(&h, "tomb");
    docs.publish_default(&id);
    open(&h).await;
    let (code, pkce) = code_for(&h, &id, &session).await;
    assert_eq!(redeem(&h, &id, &code, &pkce).await.0, StatusCode::OK);

    h.engine.revoke_oauth_client(&id).await.unwrap();
    assert!(row(&id).await.unwrap().revoked);

    let fetched = docs.fetches();
    let resp = authorize(&h, &id, Some(&session)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(docs.fetches(), fetched, "a tombstone is refused before any fetch");

    // Even a caller that already holds a validated document cannot revive it.
    let meta = CimdMetadata {
        client_id: id.clone(),
        client_name: "Revived".into(),
        client_uri: None,
        logo_uri: None,
        redirect_uris: vec![CLIENT_REDIRECT.into()],
        grant_types: vec!["authorization_code".into()],
        scopes: None,
    };
    let reg = h.registration_id;
    let err = h
        .engine
        .create_consent_flow(ConsentFlowRequest {
            client_id: id.clone(),
            identity_id: h.identity_id().await,
            session_id: Uuid::now_v7(),
            account_id: None,
            registration_id: reg,
            resource_uri: h.resource_uri.clone(),
            scopes: vec!["mcp:read".into()],
            redirect_uri: CLIENT_REDIRECT.into(),
            state: None,
            nonce: None,
            code_challenge: Pkce::generate().challenge,
            code_challenge_method: "S256".into(),
            cimd: Some(meta),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, surge_engine::AuthError::Forbidden), "{err:?}");
    let r = row(&id).await.unwrap();
    assert!(r.revoked);
    assert_eq!(r.name, "CIMD app");

    // The sweep never deletes a tombstone, however old.
    backdate(&id).await;
    h.engine.gc_unused_cimd_clients(Duration::from_secs(3600)).await.unwrap();
    assert!(row(&id).await.is_some());
}

async fn backdate(id: &str) {
    let old = chrono::Utc::now() - chrono::Duration::hours(2);
    diesel::update(oauth_client::table.find(id))
        .set((
            oauth_client::created_at.eq(old),
            oauth_client::last_used_at.eq(old),
        ))
        .execute(&mut db().await)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn the_sweep_removes_stale_unused_rows_and_keeps_everything_referenced() {
    let docs = CimdDocs::new();
    let h = harness_cimd(&docs).await;
    let session = h.sign_in().await;
    let stale = cimd_url(&h, "stale");
    let fresh = cimd_url(&h, "fresh");
    let live_flow = cimd_url(&h, "flow");
    let granted = cimd_url(&h, "granted");
    for id in [&stale, &fresh, &live_flow, &granted] {
        docs.publish_default(id);
    }
    allow(&h, &[&stale, &fresh, &live_flow, &granted]).await;

    // Each of these gets a row by starting a flow.
    for id in [&stale, &fresh, &live_flow, &granted] {
        authorize(&h, id, Some(&session)).await;
    }
    // `granted` completes consent and so is referenced by a consent and a
    // code; `stale` and `fresh` have their flows removed so nothing refers
    // to them; `live_flow` keeps its pending flow.
    let (_code, _pkce) = code_for(&h, &granted, &session).await;
    diesel::sql_query("DELETE FROM surge.oauth_consent_flow WHERE client_id = ANY($1)")
        .bind::<diesel::sql_types::Array<diesel::sql_types::Text>, _>(vec![stale.clone(), fresh.clone()])
        .execute(&mut db().await)
        .await
        .unwrap();
    for id in [&stale, &live_flow, &granted] {
        backdate(id).await;
    }

    h.engine.gc_unused_cimd_clients(Duration::from_secs(3600)).await.unwrap();
    assert!(row(&stale).await.is_none(), "stale and unreferenced: swept");
    assert!(row(&fresh).await.is_some(), "recent: kept");
    assert!(row(&live_flow).await.is_some(), "a live consent flow keeps its client");
    assert!(row(&granted).await.is_some(), "a referenced grant keeps its client");

    // A swept client simply comes back on its next authorization.
    let resp = authorize(&h, &stale, Some(&session)).await;
    assert!(query_param(&location(&resp), "consent_flow").is_some());
    assert!(row(&stale).await.is_some());
}

#[tokio::test]
#[ignore = "requires a live Postgres via DATABASE_URL"]
async fn the_database_refuses_a_first_party_or_confidential_cimd_row() {
    let h = harness().await;
    let id = cimd_url(&h, "constraint");
    let insert = |first_party: bool, auth: &'static str, source: &'static str, id: String| async move {
        diesel::sql_query(
            "INSERT INTO surge.oauth_client \
             (client_id, client_name, redirect_uris, token_endpoint_auth_method, \
              registration_source, first_party, trust_state, scope_ceiling_explicit) \
             VALUES ($1, 'x', ARRAY['https://a.test/cb'], $2, $3, $4, 'untrusted', true)",
        )
        .bind::<diesel::sql_types::Text, _>(id)
        .bind::<diesel::sql_types::Text, _>(auth)
        .bind::<diesel::sql_types::Text, _>(source)
        .bind::<diesel::sql_types::Bool, _>(first_party)
        .execute(&mut db().await)
        .await
    };
    assert!(insert(true, "none", "cimd", id.clone()).await.is_err());
    assert!(insert(false, "client_secret_basic", "cimd", id.clone()).await.is_err());
    // An https ID is a CIMD ID and nothing else; a CIMD row needs one.
    assert!(insert(false, "none", "dynamic", id.clone()).await.is_err());
    assert!(insert(false, "none", "cimd", "aeg_cid_notaurl".into()).await.is_err());
    assert!(insert(false, "none", "cimd", id).await.is_ok());
}
