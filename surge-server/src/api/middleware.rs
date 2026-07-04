use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::api::AppState;

#[derive(Clone)]
pub struct ServiceAuth {
    pub service_id: uuid::Uuid,
    pub service_name: String,
    pub grants: Vec<String>,
}

pub async fn service_auth(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match token {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "missing_service_token"})),
            )
                .into_response()
        }
    };

    let hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hasher.finalize().to_vec()
    };

    match state.engine.verify_service_token(&hash).await {
        Ok(svc) => {
            req.extensions_mut().insert(ServiceAuth {
                service_id: svc.id,
                service_name: svc.name.clone(),
                grants: svc.grants.clone(),
            });
            next.run(req).await
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid_service_token"})),
        )
            .into_response(),
    }
}

pub fn require_grant(auth: &ServiceAuth, grant: &str) -> Result<(), Response> {
    if auth.grants.contains(&grant.to_string()) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "forbidden", "message": format!("missing grant: {grant}")})),
        )
            .into_response())
    }
}
