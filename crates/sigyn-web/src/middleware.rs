use axum::extract::Request;
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;

use crate::error::WebError;
use crate::state::AppState;

/// Extract session token from the cookie header.
pub fn extract_session_token(req: &Request) -> Option<String> {
    req.headers()
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|cookie| {
            let cookie = cookie.trim();
            cookie.strip_prefix("sigyn_session=").map(|v| v.to_string())
        })
}

/// Auth guard middleware — rejects requests without a valid session.
pub async fn require_auth(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, WebError> {
    let token = extract_session_token(&req)
        .ok_or_else(|| WebError::Unauthorized("no session cookie".into()))?;

    if !state.sessions.get_and_touch(&token) {
        return Err(WebError::Unauthorized("session expired or invalid".into()));
    }

    Ok(next.run(req).await)
}
