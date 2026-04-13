use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug)]
pub enum WebError {
    /// Authentication required (no session or expired)
    Unauthorized(String),
    /// Access denied by policy engine
    Forbidden(String),
    /// Resource not found (vault, secret, identity)
    NotFound(String),
    /// Bad request (invalid input)
    BadRequest(String),
    /// Rate limited (too many login attempts)
    RateLimited,
    /// Internal error (crypto, I/O, etc.)
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    code: u16,
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            WebError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            WebError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            WebError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            WebError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            WebError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "too many login attempts, try again later".into(),
            ),
            WebError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = ErrorBody {
            error: message,
            code: status.as_u16(),
        };

        (status, axum::Json(body)).into_response()
    }
}

impl From<sigyn_engine::SigynError> for WebError {
    fn from(err: sigyn_engine::SigynError) -> Self {
        use sigyn_engine::SigynError::*;
        match &err {
            IdentityNotFound(_) => WebError::NotFound(err.to_string()),
            IdentityAlreadyExists(_) => WebError::BadRequest(err.to_string()),
            Decryption(_) => WebError::Unauthorized("decryption failed (wrong passphrase?)".into()),
            SignatureVerification => WebError::Forbidden("signature verification failed".into()),
            _ => WebError::Internal(err.to_string()),
        }
    }
}

impl From<anyhow::Error> for WebError {
    fn from(err: anyhow::Error) -> Self {
        WebError::Internal(err.to_string())
    }
}
