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

/// Required so `AuthError` can be used as the error type of a
/// `diesel_async` `transaction()` closure (its rollback machinery needs
/// `E: From<diesel::result::Error>`). Call sites that need a specific
/// mapping (e.g. `UniqueViolation` -> `UsernameTaken`) should map the error
/// explicitly before returning rather than relying on this generic fallback.
impl From<diesel::result::Error> for AuthError {
    fn from(e: diesel::result::Error) -> Self {
        match e {
            diesel::result::Error::NotFound => AuthError::NotFound,
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => AuthError::UsernameTaken,
            other => AuthError::Internal(other.into()),
        }
    }
}
