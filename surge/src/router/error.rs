use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::AuthError;

pub struct ApiError(pub AuthError);

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self.0 {
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "invalid_token"),
            AuthError::SessionExpired => (StatusCode::UNAUTHORIZED, "session_expired"),
            AuthError::IdentityDisabled => (StatusCode::FORBIDDEN, "identity_disabled"),
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            AuthError::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            AuthError::UsernameTaken => (StatusCode::CONFLICT, "username_taken"),
            AuthError::Validation(_) => (StatusCode::UNPROCESSABLE_ENTITY, "validation_error"),
            AuthError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            AuthError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            AuthError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            AuthError::Timeout => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
            AuthError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        let mut body = json!({ "error": code });
        if let AuthError::RateLimited { retry_after } = &self.0 {
            body["retry_after"] = json!(retry_after.as_secs());
        }
        if let AuthError::Validation(v) = &self.0 {
            body["message"] = json!(v.to_string());
        }

        (status, Json(body)).into_response()
    }
}
