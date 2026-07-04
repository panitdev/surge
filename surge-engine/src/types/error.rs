use std::time::Duration;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    #[error("invalid token")]
    InvalidToken,

    #[error("session expired")]
    SessionExpired,

    #[error("identity disabled")]
    IdentityDisabled,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("rate limited")]
    RateLimited { retry_after: Duration },

    #[error("username taken")]
    UsernameTaken,

    #[error("validation error: {0}")]
    Validation(ValidationError),

    #[error("not found")]
    NotFound,

    #[error("forbidden")]
    Forbidden,

    #[error("service unavailable")]
    Unavailable,

    #[error("request timeout")]
    Timeout,

    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("username: {0}")]
    Username(#[from] super::username::UsernameError),

    #[error("password: {0}")]
    Password(#[from] super::password::PasswordError),

    #[error("{field}: {message}")]
    Field { field: &'static str, message: String },
}

impl From<ValidationError> for AuthError {
    fn from(e: ValidationError) -> Self {
        AuthError::Validation(e)
    }
}
