//! OAuth error responses.
//!
//! Two shapes, and which one applies is a security decision rather than a
//! formatting one. Once the client and its `redirect_uri` are validated,
//! errors go back to the client as a redirect (RFC 6749 §4.1.2.1) carrying
//! `state`, because that is the only channel the client is listening on.
//! *Before* that point they must be rendered here, on the AS's own origin: an
//! unvalidated `redirect_uri` is an open redirect, and handing one an error
//! is still handing it a redirect.

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use serde_json::json;
use surge_engine::AuthError;

/// The RFC 6749 §5.2 / RFC 6750 error codes this server emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OauthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
    InvalidScope,
    AccessDenied,
    InvalidTarget,
    InvalidToken,
    ConsentRequired,
    LoginRequired,
    InvalidRedirectUri,
    InvalidClientMetadata,
    ServerError,
    TemporarilyUnavailable,
}

impl OauthErrorCode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidToken => "invalid_token",
            Self::ConsentRequired => "consent_required",
            Self::LoginRequired => "login_required",
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::InvalidClientMetadata => "invalid_client_metadata",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::InvalidClient | Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::AccessDenied => StatusCode::FORBIDDEN,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

/// A direct (non-redirect) OAuth error: the token, introspection, revocation,
/// registration and userinfo endpoints all answer in this shape.
#[derive(Debug)]
pub(crate) struct OauthError {
    pub code: OauthErrorCode,
    pub description: String,
    /// Set for 401s so the response carries a `WWW-Authenticate` challenge.
    pub bearer_challenge: bool,
}

impl OauthError {
    pub(crate) fn new(code: OauthErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
            bearer_challenge: false,
        }
    }

    pub(crate) fn bearer(code: OauthErrorCode, description: impl Into<String>) -> Self {
        Self {
            bearer_challenge: true,
            ..Self::new(code, description)
        }
    }

    pub(crate) fn server(context: &str) -> Self {
        Self::new(OauthErrorCode::ServerError, context)
    }
}

impl IntoResponse for OauthError {
    fn into_response(self) -> Response {
        let body = json!({
            "error": self.code.as_str(),
            "error_description": self.description,
        });

        let mut response = (self.code.status(), Json(body)).into_response();
        if self.bearer_challenge {
            let challenge = format!(
                "Bearer error=\"{}\", error_description=\"{}\"",
                self.code.as_str(),
                self.description.replace('"', "'")
            );
            if let Ok(value) = challenge.parse() {
                response
                    .headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, value);
            }
        }
        response
    }
}

impl From<AuthError> for OauthError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::NotFound => Self::new(OauthErrorCode::InvalidRequest, "not found"),
            AuthError::InvalidToken | AuthError::SessionExpired => {
                Self::new(OauthErrorCode::InvalidGrant, "the grant is not valid")
            }
            AuthError::InvalidCredentials => {
                Self::new(OauthErrorCode::InvalidClient, "client authentication failed")
            }
            AuthError::IdentityDisabled => {
                Self::new(OauthErrorCode::AccessDenied, "the account is disabled")
            }
            AuthError::Forbidden => Self::new(OauthErrorCode::AccessDenied, "forbidden"),
            AuthError::RateLimited { retry_after } => Self::new(
                OauthErrorCode::TemporarilyUnavailable,
                format!("rate limited; retry in {}s", retry_after.as_secs()),
            ),
            AuthError::Validation(v) => Self::new(OauthErrorCode::InvalidRequest, v.to_string()),
            other => Self::server(&other.to_string()),
        }
    }
}

/// An error the client must be told about *before* its `redirect_uri` has
/// been validated — so it is rendered here rather than redirected anywhere.
/// Deliberately plain: this page exists to be read by a developer looking at
/// a browser, not to be pretty.
pub(crate) fn authorize_error_page(code: OauthErrorCode, description: &str) -> Response {
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>Authorization error</title></head><body>\
         <h1>Authorization error</h1><p><code>{}</code></p><p>{}</p>\
         <p>This request was not redirected anywhere, because the client or its \
         redirect URI could not be verified.</p></body></html>",
        escape(code.as_str()),
        escape(description),
    );
    (code.status(), Html(body)).into_response()
}

/// An error the client *should* receive on its validated redirect URI.
pub(crate) fn authorize_error_redirect(
    redirect_uri: &str,
    code: OauthErrorCode,
    description: &str,
    state: Option<&str>,
) -> Response {
    match build_redirect(redirect_uri, |q| {
        q.append_pair("error", code.as_str());
        q.append_pair("error_description", description);
        if let Some(state) = state {
            q.append_pair("state", state);
        }
    }) {
        Some(url) => Redirect::to(&url).into_response(),
        // The URI passed exact-match validation at registration, so failing
        // to parse it here means something is badly wrong; falling back to
        // the page is the only safe move left.
        None => authorize_error_page(code, description),
    }
}

/// Appends query parameters to a redirect URI, preserving any it already has.
pub(crate) fn build_redirect(
    redirect_uri: &str,
    build: impl FnOnce(&mut url::form_urlencoded::Serializer<'_, url::UrlQuery<'_>>),
) -> Option<String> {
    let mut url = url::Url::parse(redirect_uri).ok()?;
    {
        let mut pairs = url.query_pairs_mut();
        build(&mut pairs);
    }
    Some(url.to_string())
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
