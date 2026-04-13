use axum::extract::State;
use axum::Json;
use serde::Serialize;

use sigyn_engine::identity::keygen::IdentityStore;

use crate::error::WebError;
use crate::state::AppState;

#[derive(Serialize)]
pub struct IdentityInfo {
    pub fingerprint: String,
    pub name: String,
    pub email: Option<String>,
}

pub async fn list_identities(
    State(state): State<AppState>,
) -> Result<Json<Vec<IdentityInfo>>, WebError> {
    let store = IdentityStore::new(state.sigyn_home.clone());
    let identities = store
        .list()
        .map_err(|e| WebError::Internal(format!("failed to list identities: {}", e)))?;

    let result: Vec<IdentityInfo> = identities
        .into_iter()
        .map(|id| IdentityInfo {
            fingerprint: id.fingerprint.to_hex(),
            name: id.profile.name,
            email: id.profile.email.filter(|e| !e.is_empty()),
        })
        .collect();

    Ok(Json(result))
}
