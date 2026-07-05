use std::sync::Arc;

use axum::Router;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use secrecy::SecretString;
use serde::Deserialize;
use surge::{AuthError, AuthProvider, Password, RegisterRequest, Session, SessionToken, Username};

const COOKIE_NAME: &str = "surge_session";

#[derive(Clone)]
pub struct AppState {
    auth: Arc<dyn AuthProvider>,
}

impl AppState {
    pub fn new(auth: Arc<dyn AuthProvider>) -> Self {
        Self { auth }
    }
}

impl AsRef<Arc<dyn AuthProvider>> for AppState {
    fn as_ref(&self) -> &Arc<dyn AuthProvider> {
        &self.auth
    }
}

pub fn app(auth: Arc<dyn AuthProvider>) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/login", post(login))
        .route("/signup", post(signup))
        .route("/logout", post(logout))
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .with_state(AppState::new(auth))
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct SignupForm {
    username: String,
    display_name: String,
    password: String,
}

async fn home(State(state): State<AppState>, jar: CookieJar) -> Response {
    match current_session(&state, &jar).await {
        Ok(Some(session)) => render_page(StatusCode::OK, Some(&session), None),
        Ok(None) | Err(AuthError::InvalidToken | AuthError::SessionExpired) => {
            render_page(StatusCode::OK, None, None)
        }
        Err(error) => render_page(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            Some(error_message(&error)),
        ),
    }
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    let result = credentials(&form.username, &form.password);
    let result = match result {
        Ok((username, password)) => state.auth.authenticate_password(&username, &password).await,
        Err(error) => Err(error),
    };

    match result {
        Ok((_session, token)) => {
            (jar.add(session_cookie(&token)), Redirect::to("/")).into_response()
        }
        Err(error) => render_page(status_for(&error), None, Some(error_message(&error))),
    }
}

async fn signup(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<SignupForm>,
) -> Response {
    let username = match Username::new(&form.username) {
        Ok(username) => username,
        Err(error) => {
            return render_page(
                StatusCode::UNPROCESSABLE_ENTITY,
                None,
                Some(error.to_string()),
            );
        }
    };
    let password_secret = SecretString::from(form.password);
    let password = match Password::new(password_secret.clone()) {
        Ok(password) => password,
        Err(error) => {
            return render_page(
                StatusCode::UNPROCESSABLE_ENTITY,
                None,
                Some(error.to_string()),
            );
        }
    };
    let login_password = match Password::new(password_secret) {
        Ok(password) => password,
        Err(error) => {
            return render_page(
                StatusCode::UNPROCESSABLE_ENTITY,
                None,
                Some(error.to_string()),
            );
        }
    };

    let display_name = form.display_name.trim();
    if display_name.is_empty() || display_name.chars().count() > 100 {
        return render_page(
            StatusCode::UNPROCESSABLE_ENTITY,
            None,
            Some("display name must be 1-100 characters".into()),
        );
    }

    let request = RegisterRequest {
        username: username.clone(),
        password,
        display_name: display_name.to_owned(),
    };

    if let Err(error) = state.auth.register(request).await {
        return render_page(status_for(&error), None, Some(error_message(&error)));
    }

    match state
        .auth
        .authenticate_password(&username, &login_password)
        .await
    {
        Ok((_session, token)) => {
            (jar.add(session_cookie(&token)), Redirect::to("/")).into_response()
        }
        Err(error) => render_page(status_for(&error), None, Some(error_message(&error))),
    }
}

async fn logout(State(state): State<AppState>, jar: CookieJar) -> Response {
    if let Some(token) = token_from_jar(&jar) {
        let _ = state.auth.revoke_session(&token).await;
    }

    let removal = Cookie::build((COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::ZERO)
        .build();
    (jar.add(removal), Redirect::to("/")).into_response()
}

fn credentials(username: &str, password: &str) -> Result<(Username, Password), AuthError> {
    let username = Username::new(username).map_err(|_| AuthError::InvalidCredentials)?;
    let password = Password::new(SecretString::from(password.to_owned()))
        .map_err(|_| AuthError::InvalidCredentials)?;
    Ok((username, password))
}

async fn current_session(state: &AppState, jar: &CookieJar) -> Result<Option<Session>, AuthError> {
    let Some(token) = token_from_jar(jar) else {
        return Ok(None);
    };
    state.auth.verify_session(&token).await.map(Some)
}

fn token_from_jar(jar: &CookieJar) -> Option<SessionToken> {
    SessionToken::from_raw(jar.get(COOKIE_NAME)?.value())
}

fn session_cookie(token: &SessionToken) -> Cookie<'static> {
    Cookie::build((COOKIE_NAME, token.expose_secret().to_owned()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build()
}

fn status_for(error: &AuthError) -> StatusCode {
    match error {
        AuthError::InvalidCredentials | AuthError::InvalidToken | AuthError::SessionExpired => {
            StatusCode::UNAUTHORIZED
        }
        AuthError::UsernameTaken => StatusCode::CONFLICT,
        AuthError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
        AuthError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
        AuthError::Unavailable | AuthError::Timeout => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn error_message(error: &AuthError) -> String {
    match error {
        AuthError::InvalidCredentials => "Invalid username or password.".into(),
        AuthError::UsernameTaken => "That username is already taken.".into(),
        AuthError::Validation(error) => error.to_string(),
        AuthError::RateLimited { retry_after } => {
            format!(
                "Too many attempts. Try again in {} seconds.",
                retry_after.as_secs()
            )
        }
        AuthError::Unavailable | AuthError::Timeout => {
            "Authentication is temporarily unavailable.".into()
        }
        _ => "Authentication failed.".into(),
    }
}

fn render_page(status: StatusCode, session: Option<&Session>, error: Option<String>) -> Response {
    let content = if let Some(session) = session {
        format!(
            r#"<section class="card"><p class="eyebrow">Signed in</p><h1>Hello, {}.</h1><p>You are authenticated as <strong>@{}</strong>.</p><form method="post" action="/logout"><button type="submit" class="secondary">Sign out</button></form></section>"#,
            escape_html(&session.identity.display_name),
            escape_html(session.identity.username.as_str()),
        )
    } else {
        let alert = error
            .map(|message| {
                format!(
                    r#"<p class="error" role="alert">{}</p>"#,
                    escape_html(&message)
                )
            })
            .unwrap_or_default();
        format!(
            r#"<header><p class="eyebrow">Surge demo</p><h1>One UI, two deployment modes.</h1><p>Sign in to an existing account or create one below.</p></header>{alert}<main><section class="card"><h2>Sign in</h2><form method="post" action="/login"><label>Username<input name="username" autocomplete="username" required minlength="3" maxlength="32"></label><label>Password<input name="password" type="password" autocomplete="current-password" required minlength="8"></label><button type="submit">Sign in</button></form></section><section class="card"><h2>Create account</h2><form method="post" action="/signup"><label>Username<input name="username" autocomplete="username" required minlength="3" maxlength="32" pattern="[A-Za-z0-9-]+"></label><label>Display name<input name="display_name" autocomplete="name" required maxlength="100"></label><label>Password<input name="password" type="password" autocomplete="new-password" required minlength="8"></label><button type="submit">Sign up</button></form></section></main>"#,
        )
    };

    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Surge demo</title><style>:root{{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#17212b;background:#eef3f1}}*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;padding:2rem}}.shell{{width:min(860px,100%)}}header{{margin-bottom:1.5rem}}h1{{font-size:clamp(2rem,5vw,3.5rem);line-height:1.05;margin:.25rem 0}}h2{{margin-top:0}}p{{color:#52606d}}.eyebrow{{color:#087f5b;font-weight:800;letter-spacing:.12em;text-transform:uppercase;font-size:.75rem}}main{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}}.card{{background:white;border:1px solid #dce5e1;border-radius:18px;padding:1.5rem;box-shadow:0 18px 50px #173f3220}}form{{display:grid;gap:1rem}}label{{display:grid;gap:.4rem;font-weight:650}}input{{font:inherit;padding:.75rem;border:1px solid #b8c6c1;border-radius:9px}}input:focus{{outline:3px solid #63e6be66;border-color:#087f5b}}button{{font:inherit;font-weight:750;color:white;background:#087f5b;border:0;border-radius:9px;padding:.8rem 1rem;cursor:pointer}}button:hover{{background:#066649}}button.secondary{{background:#334e46}}.error{{background:#fff1f0;color:#a61b1b;border:1px solid #ffc9c5;border-radius:9px;padding:.8rem 1rem}}</style></head><body><div class="shell">{content}</div></body></html>"#,
    );
    (status, Html(html)).into_response()
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::escape_html;

    #[test]
    fn escapes_user_content() {
        assert_eq!(
            escape_html("<script>'x' & \"y\"</script>"),
            "&lt;script&gt;&#39;x&#39; &amp; &quot;y&quot;&lt;/script&gt;"
        );
    }
}
