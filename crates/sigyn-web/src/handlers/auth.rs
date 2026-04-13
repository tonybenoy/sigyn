use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use sigyn_engine::crypto::keys::KeyFingerprint;
use sigyn_engine::identity::keygen::IdentityStore;

use crate::error::WebError;
use crate::middleware::extract_session_token;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub fingerprint: String,
    pub passphrase: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub identity_name: String,
    pub fingerprint: String,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub authenticated: bool,
    pub identity_name: Option<String>,
    pub fingerprint: Option<String>,
}

pub async fn login(
    State(state): State<AppState>,
    Json(mut req): Json<LoginRequest>,
) -> Result<impl IntoResponse, WebError> {
    // Rate limit check
    if state.sessions.is_rate_limited(&req.fingerprint) {
        return Err(WebError::RateLimited);
    }

    let fp_bytes = hex::decode(&req.fingerprint)
        .map_err(|_| WebError::BadRequest("invalid fingerprint hex".into()))?;
    if fp_bytes.len() != 16 {
        return Err(WebError::BadRequest("fingerprint must be 16 bytes".into()));
    }
    let mut fp_arr = [0u8; 16];
    fp_arr.copy_from_slice(&fp_bytes);
    let fingerprint = KeyFingerprint(fp_arr);

    let store = IdentityStore::new(state.sigyn_home.clone());

    // Attempt to load (decrypt) the identity with the provided passphrase
    let loaded = match store.load(&fingerprint, &req.passphrase) {
        Ok(loaded) => {
            // Zeroize passphrase from request as soon as possible
            req.passphrase.clear();
            loaded
        }
        Err(_) => {
            req.passphrase.clear();
            state.sessions.record_failed_login(&req.fingerprint);
            return Err(WebError::Unauthorized("invalid passphrase".into()));
        }
    };

    state.sessions.clear_rate_limit(&req.fingerprint);

    let identity_name = loaded.identity.profile.name.clone();
    let fp_hex = fingerprint.to_hex();
    let token = state
        .sessions
        .create(loaded, fingerprint, identity_name.clone());

    let cookie = format!(
        "sigyn_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        token,
        state.session_timeout.as_secs()
    );

    let body = LoginResponse {
        identity_name,
        fingerprint: fp_hex,
    };

    Ok(([(header::SET_COOKIE, cookie)], Json(body)))
}

pub async fn logout(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Result<impl IntoResponse, WebError> {
    if let Some(token) = extract_session_token(&req) {
        state.sessions.destroy(&token);
    }

    let clear_cookie = "sigyn_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";

    Ok((
        [(header::SET_COOKIE, clear_cookie)],
        Json(serde_json::json!({"ok": true})),
    ))
}

pub async fn status(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Result<Json<StatusResponse>, WebError> {
    let token = extract_session_token(&req);

    let resp = match token {
        Some(ref t) => state
            .sessions
            .with_session(t, |session| StatusResponse {
                authenticated: true,
                identity_name: Some(session.identity_name.clone()),
                fingerprint: Some(session.fingerprint.to_hex()),
            })
            .unwrap_or(StatusResponse {
                authenticated: false,
                identity_name: None,
                fingerprint: None,
            }),
        None => StatusResponse {
            authenticated: false,
            identity_name: None,
            fingerprint: None,
        },
    };

    Ok(Json(resp))
}
