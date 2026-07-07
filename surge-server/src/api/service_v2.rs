//! Service-facing v2 scaffold (architecture.md §4). No behavior differs
//! from v1 yet — this exists so the two-versions-live-at-once shape is in
//! place before there's any actual divergence to carry. It reuses v1's
//! handlers directly rather than duplicating them: until v2 needs its own
//! logic, "v2" is just a second name for the same behavior, mounted at its
//! own path so it can be retired or diverge independently later.
use std::sync::Arc;

use axum::middleware;
use axum::routing::{get, patch, post};
use axum::Router;

use super::middleware::service_auth;
use super::service_v1::{
    authenticate_password, get_identity, get_identity_by_username, register,
    register_and_authenticate, revoke_all_sessions, revoke_session, update_profile,
    verify_session,
};
use super::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/sessions/verify", post(verify_session))
        .route("/sessions/revoke", post(revoke_session))
        .route(
            "/identities/{id}/revoke-sessions",
            post(revoke_all_sessions),
        )
        .route("/identities/{id}", get(get_identity))
        .route("/identities", get(get_identity_by_username))
        .route("/identities/{id}/profile", patch(update_profile))
        .route("/register", post(register))
        .route(
            "/register-and-authenticate",
            post(register_and_authenticate),
        )
        .route("/authenticate/password", post(authenticate_password))
        .layer(middleware::from_fn_with_state(state.clone(), service_auth))
        .with_state(state)
}
