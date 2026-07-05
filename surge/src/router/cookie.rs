use axum_extra::extract::cookie::{Cookie, SameSite};

pub(crate) fn session_cookie(token: &str, domain: &str, max_age_secs: i64) -> Cookie<'static> {
    Cookie::build(("surge_session", token.to_string()))
        .domain(domain.to_string())
        .path("/")
        .max_age(time::Duration::seconds(max_age_secs))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build()
}

pub(crate) fn removal_cookie(domain: &str) -> Cookie<'static> {
    Cookie::build(("surge_session", ""))
        .domain(domain.to_string())
        .path("/")
        .max_age(time::Duration::ZERO)
        .http_only(true)
        .secure(true)
        .build()
}
