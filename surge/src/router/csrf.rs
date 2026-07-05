use crate::AuthError;

/// Compares a login flow's stored CSRF token against the one submitted
/// with a credential-entry request.
pub(crate) fn check_flow_csrf(expected: &str, provided: &str) -> Result<(), AuthError> {
    if expected == provided {
        Ok(())
    } else {
        Err(AuthError::Forbidden)
    }
}
