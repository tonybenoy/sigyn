use axum::extract::State;
use axum::Json;
use serde::Serialize;

use sigyn_engine::identity::keygen::IdentityStore;

use crate::error::WebError;
use crate::middleware::extract_session_token;
use crate::state::AppState;

#[derive(Serialize)]
pub struct IdentityInfo {
    pub fingerprint: String,
    pub name: String,
    pub email: Option<String>,
}

/// List identities. This route stays reachable without a session because the
/// login screen needs the identity picker (name + fingerprint) before any
/// session exists, and login itself posts the fingerprint. Everything beyond
/// that minimum — currently the email — is only returned to authenticated
/// sessions.
pub async fn list_identities(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Result<Json<Vec<IdentityInfo>>, WebError> {
    let authenticated = extract_session_token(&req)
        .map(|token| state.sessions.get_and_touch(&token))
        .unwrap_or(false);

    let store = IdentityStore::new(state.sigyn_home.clone());
    let identities = store
        .list()
        .map_err(|e| WebError::Internal(format!("failed to list identities: {}", e)))?;

    let result: Vec<IdentityInfo> = identities
        .into_iter()
        .map(|id| IdentityInfo {
            fingerprint: id.fingerprint.to_hex(),
            name: id.profile.name,
            email: if authenticated {
                id.profile.email.filter(|e| !e.is_empty())
            } else {
                None
            },
        })
        .collect();

    Ok(Json(result))
}
