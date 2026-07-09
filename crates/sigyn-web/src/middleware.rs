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

/// Host guard middleware — rejects any request whose Host header does not
/// name this server (`127.0.0.1` or `localhost`, optionally with the bound
/// port). This defends against DNS-rebinding attacks: a page on evil.com can
/// re-point its DNS at 127.0.0.1 and issue "same-origin" requests to the
/// local server, but the browser still sends `Host: evil.com`, which is
/// rejected here.
pub async fn validate_host(
    req: Request,
    next: Next,
    bound_port: u16,
) -> Result<Response, WebError> {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        // HTTP/2 carries the authority in the URI instead of a Host header.
        .or_else(|| req.uri().authority().map(|a| a.to_string()));

    match host {
        Some(h) if host_is_allowed(&h, bound_port) => Ok(next.run(req).await),
        _ => Err(WebError::Forbidden("invalid Host header".into())),
    }
}

/// Check that a Host header value is `127.0.0.1` or `localhost`, with either
/// no port or exactly the port the server is bound to.
fn host_is_allowed(host: &str, bound_port: u16) -> bool {
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };

    let name_ok = name == "127.0.0.1" || name.eq_ignore_ascii_case("localhost");
    let port_ok = match port {
        None => true,
        Some(p) => p.parse::<u16>().map(|p| p == bound_port).unwrap_or(false),
    };

    name_ok && port_ok
}

#[cfg(test)]
mod tests {
    use super::host_is_allowed;

    #[test]
    fn test_host_allowed() {
        assert!(host_is_allowed("127.0.0.1", 8080));
        assert!(host_is_allowed("127.0.0.1:8080", 8080));
        assert!(host_is_allowed("localhost", 8080));
        assert!(host_is_allowed("localhost:8080", 8080));
        assert!(host_is_allowed("LocalHost:8080", 8080));
    }

    #[test]
    fn test_host_rejected() {
        assert!(!host_is_allowed("evil.com", 8080));
        assert!(!host_is_allowed("evil.com:8080", 8080));
        assert!(!host_is_allowed("127.0.0.1:9999", 8080));
        assert!(!host_is_allowed("localhost:9999", 8080));
        assert!(!host_is_allowed("127.0.0.1:", 8080));
        assert!(!host_is_allowed("127.0.0.1.evil.com", 8080));
        assert!(!host_is_allowed("localhost.evil.com:8080", 8080));
        assert!(!host_is_allowed("", 8080));
        assert!(!host_is_allowed("[::1]:8080", 8080));
    }
}
