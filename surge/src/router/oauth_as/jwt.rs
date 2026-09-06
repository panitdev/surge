//! Access-token and ID-token minting and verification.
//!
//! Access tokens are JWTs so a resource server can verify them offline
//! against JWKS: an MCP server is the audience for every request on a
//! connection and should not need a network hop per call. The cost of that
//! choice is that a signed token cannot be recalled mid-flight, which is why
//! the lifetime is short and why `/oauth2/introspect` exists for callers that
//! need an authoritative answer instead of a fast one.

use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use surge_engine::oauth::SigningKeyMaterial;
use uuid::Uuid;

use super::error::{OauthError, OauthErrorCode};

/// RFC 9068 §2.1: an access token declares its own type, so a resource server
/// can refuse an ID token presented as one.
const ACCESS_TOKEN_TYPE: &str = "at+jwt";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccessClaims {
    pub iss: String,
    /// The identity UUID — the same subject the Hydra bridge uses, so tokens
    /// from both issuers name the same person during a cutover (§9).
    pub sub: String,
    /// Single-valued: a token minted for resource A must not validate at
    /// resource B, and an array invites exactly that.
    pub aud: String,
    pub client_id: String,
    pub scope: String,
    /// The session the grant was authorized from. Audit and traceability; the
    /// grant itself is bound to the identity (internal/oauth-as.md §7).
    pub sid: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IdClaims {
    pub iss: String,
    pub sub: String,
    /// An ID token is *for the client*, so its audience is the client id —
    /// not the resource the access token is scoped to.
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

pub(crate) struct MintedAccessToken {
    pub token: String,
    pub expires_in: i64,
}

pub(crate) struct AccessTokenSpec<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub audience: &'a str,
    pub client_id: &'a str,
    pub scopes: &'a [String],
    pub session_id: &'a str,
    pub ttl: Duration,
}

pub(crate) fn sign_access_token(
    key: &SigningKeyMaterial,
    spec: AccessTokenSpec<'_>,
) -> Result<MintedAccessToken, OauthError> {
    let now = chrono::Utc::now().timestamp();
    let ttl = spec.ttl.as_secs() as i64;

    let claims = AccessClaims {
        iss: spec.issuer.to_string(),
        sub: spec.subject.to_string(),
        aud: spec.audience.to_string(),
        client_id: spec.client_id.to_string(),
        scope: spec.scopes.join(" "),
        sid: spec.session_id.to_string(),
        jti: Uuid::new_v4().to_string(),
        iat: now,
        exp: now + ttl,
    };

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key.kid.clone());
    header.typ = Some(ACCESS_TOKEN_TYPE.to_string());

    let token = jsonwebtoken::encode(&header, &claims, &encoding_key(key))
        .map_err(|e| OauthError::server(&format!("failed to sign access token: {e}")))?;

    Ok(MintedAccessToken {
        token,
        expires_in: ttl,
    })
}

pub(crate) fn sign_id_token(
    key: &SigningKeyMaterial,
    claims: IdClaims,
) -> Result<String, OauthError> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key.kid.clone());

    jsonwebtoken::encode(&header, &claims, &encoding_key(key))
        .map_err(|e| OauthError::server(&format!("failed to sign id token: {e}")))
}

fn encoding_key(key: &SigningKeyMaterial) -> EncodingKey {
    EncodingKey::from_ec_der(&key.pkcs8_der)
}

/// Verifies an access token's signature, issuer and expiry against the
/// published keys. The audience is checked by the *caller*, because what
/// counts as the right audience differs per endpoint: introspection asks "is
/// this one of my resources?", userinfo does not care.
pub(crate) fn verify_access_token(
    token: &str,
    issuer: &str,
    keys: &[surge_engine::oauth::PublicSigningKey],
) -> Result<AccessClaims, OauthError> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| {
        OauthError::bearer(OauthErrorCode::InvalidToken, "malformed access token")
    })?;

    // A `kid` selects the key; without one, every published key is tried,
    // which keeps tokens minted just before a rotation verifiable.
    let candidates: Vec<_> = match &header.kid {
        Some(kid) => keys.iter().filter(|k| &k.kid == kid).collect(),
        None => keys.iter().collect(),
    };
    if candidates.is_empty() {
        return Err(OauthError::bearer(
            OauthErrorCode::InvalidToken,
            "token was signed by an unknown key",
        ));
    }

    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[issuer]);
    // Audience is the caller's business; see the doc comment.
    validation.validate_aud = false;

    for key in candidates {
        let (Some(x), Some(y)) = (
            key.public_jwk.get("x").and_then(|v| v.as_str()),
            key.public_jwk.get("y").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let Ok(decoding) = DecodingKey::from_ec_components(x, y) else {
            continue;
        };
        if let Ok(data) = jsonwebtoken::decode::<AccessClaims>(token, &decoding, &validation) {
            return Ok(data.claims);
        }
    }

    Err(OauthError::bearer(
        OauthErrorCode::InvalidToken,
        "the access token is expired, malformed, or not signed by this issuer",
    ))
}

/// Pulls a bearer token out of an `Authorization` header.
pub(crate) fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}
