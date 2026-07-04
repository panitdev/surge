use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::Cookie;
use serde::Deserialize;
use serde_json::json;
use surge_engine::types::*;
use tower_http::cors::{AllowOrigin, CorsLayer};

use super::error::ApiError;
use super::AppState;
use crate::config::{RegistrationMode, ServerConfig};

pub fn router(state: Arc<AppState>, config: &ServerConfig) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact(
            config.auth_ui_origin.parse().unwrap(),
        ))
        .allow_credentials(true)
        .allow_methods([
            http::Method::GET,
            http::Method::POST,
        ])
        .allow_headers([
            http::header::CONTENT_TYPE,
            http::header::COOKIE,
        ]);

    Router::new()
        .route("/v1/login", get(start_login))
        .route("/v1/flows/{id}", get(get_flow))
        .route("/v1/flows/{id}/password", post(submit_password))
        .route("/v1/flows/{id}/register", post(submit_register))
        .route("/v1/logout", post(logout))
        .route("/v1/whoami", get(whoami))
        .layer(cors)
        .with_state(state)
}

#[derive(Deserialize)]
struct LoginQuery {
    return_to: String,
}

async fn start_login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, ApiError> {
    let origins = state.engine.all_return_origins().await?;
    let return_url = url::Url::parse(&query.return_to)
        .map_err(|_| AuthError::Validation(ValidationError::Field {
            field: "return_to",
            message: "invalid URL".into(),
        }))?;

    let return_origin = format!(
        "{}://{}",
        return_url.scheme(),
        return_url.host_str().unwrap_or("")
    );
    if let Some(port) = return_url.port() {
        let return_origin = format!("{return_origin}:{port}");
        if !origins.contains(&return_origin) {
            return Err(AuthError::Validation(ValidationError::Field {
                field: "return_to",
                message: "origin not registered".into(),
            })
            .into());
        }
    } else if !origins.contains(&return_origin) {
        return Err(AuthError::Validation(ValidationError::Field {
            field: "return_to",
            message: "origin not registered".into(),
        })
        .into());
    }

    let flow = state
        .engine
        .create_login_flow(&query.return_to)
        .await?;

    let redirect_url = format!(
        "{}/login?flow={}",
        state.config.auth_ui_origin, flow.id
    );

    Ok(Redirect::to(&redirect_url).into_response())
}

async fn get_flow(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let flow = state.engine.get_login_flow(&id).await?;

    Ok(Json(json!({
        "id": flow.id,
        "state": flow.state,
        "csrf_token": flow.csrf_token,
        "error": flow.error,
        "registration_enabled": state.config.registration != RegistrationMode::Closed,
    })))
}

#[derive(Deserialize)]
struct PasswordSubmit {
    username: String,
    password: String,
    csrf_token: String,
}

async fn submit_password(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<PasswordSubmit>,
) -> Result<Response, ApiError> {
    let flow = state.engine.get_login_flow(&id).await?;

    if flow.state != "created" {
        return Err(AuthError::InvalidToken.into());
    }
    if flow.csrf_token != body.csrf_token {
        return Err(AuthError::Forbidden.into());
    }

    let username = match Username::new(&body.username) {
        Ok(u) => u,
        Err(_) => {
            state
                .engine
                .record_flow_error(&id, "invalid_credentials")
                .await?;
            return Err(AuthError::InvalidCredentials.into());
        }
    };

    let password = match Password::new(secrecy::SecretString::from(body.password)) {
        Ok(p) => p,
        Err(_) => {
            state
                .engine
                .record_flow_error(&id, "invalid_credentials")
                .await?;
            return Err(AuthError::InvalidCredentials.into());
        }
    };

    match state
        .engine
        .authenticate_password(&username, &password, None)
        .await
    {
        Ok((session, token)) => {
            state.engine.complete_flow(&id).await?;

            let cookie = build_session_cookie(
                token.expose_secret(),
                &state.config.cookie_domain,
                state.config.session_ttl().as_secs() as i64,
            );

            let jar = CookieJar::new().add(cookie);
            Ok((
                jar,
                Json(json!({
                    "return_to": flow.return_to,
                    "session": serde_json::to_value(&session).unwrap(),
                })),
            )
                .into_response())
        }
        Err(e) => {
            state
                .engine
                .record_flow_error(&id, "invalid_credentials")
                .await?;
            Err(e.into())
        }
    }
}

#[derive(Deserialize)]
struct RegisterSubmit {
    username: String,
    password: String,
    display_name: String,
    csrf_token: String,
}

async fn submit_register(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<RegisterSubmit>,
) -> Result<Response, ApiError> {
    match state.config.registration {
        RegistrationMode::Closed => return Err(AuthError::Forbidden.into()),
        RegistrationMode::Invite => {
            return Err(AuthError::Internal(
                anyhow::anyhow!("invite-based registration is not yet implemented"),
            ).into());
        }
        RegistrationMode::Open => {}
    }

    let flow = state.engine.get_login_flow(&id).await?;
    if flow.state != "created" {
        return Err(AuthError::InvalidToken.into());
    }
    if flow.csrf_token != body.csrf_token {
        return Err(AuthError::Forbidden.into());
    }

    let username = Username::new(&body.username)
        .map_err(|e| AuthError::Validation(ValidationError::from(e)))?;
    let password = Password::new(secrecy::SecretString::from(body.password))
        .map_err(|e| AuthError::Validation(ValidationError::from(e)))?;

    let req = RegisterRequest {
        username: username.clone(),
        password,
        display_name: body.display_name,
    };

    let identity = state.engine.register(req, None).await?;

    let token = SessionToken::generate();
    let session = state
        .engine
        .create_session(identity.id, &token, AuthMethod::Password)
        .await?;

    state.engine.complete_flow(&id).await?;

    let cookie = build_session_cookie(
        token.expose_secret(),
        &state.config.cookie_domain,
        state.config.session_ttl().as_secs() as i64,
    );
    let jar = CookieJar::new().add(cookie);

    Ok((
        StatusCode::CREATED,
        jar,
        Json(json!({
            "return_to": flow.return_to,
            "session": serde_json::to_value(&session).unwrap(),
        })),
    )
        .into_response())
}

async fn logout(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    if let Some(cookie) = jar.get("surge_session") {
        if let Some(token) = SessionToken::from_raw(cookie.value()) {
            let _ = state.engine.revoke_session(&token).await;
        }
    }

    let removal = Cookie::build(("surge_session", ""))
        .domain(state.config.cookie_domain.clone())
        .path("/")
        .max_age(time::Duration::ZERO)
        .http_only(true)
        .secure(true)
        .build();

    let jar = CookieJar::new().add(removal);
    Ok((jar, StatusCode::NO_CONTENT).into_response())
}

async fn whoami(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, ApiError> {
    let cookie = jar
        .get("surge_session")
        .ok_or(AuthError::InvalidToken)?;

    let token = SessionToken::from_raw(cookie.value())
        .ok_or(AuthError::InvalidToken)?;

    let session = state.engine.verify_session(&token).await?;
    Ok(Json(serde_json::to_value(&session).unwrap()))
}

fn build_session_cookie(token: &str, domain: &str, max_age_secs: i64) -> Cookie<'static> {
    Cookie::build(("surge_session", token.to_string()))
        .domain(domain.to_string())
        .path("/")
        .max_age(time::Duration::seconds(max_age_secs))
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .build()
}
