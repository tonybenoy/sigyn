use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use sigyn_engine::audit::AuditLog;
use sigyn_engine::crypto::sealed::derive_file_cipher_with_salt;
use sigyn_engine::vault::VaultPaths;

use crate::error::WebError;
use crate::handlers::vault::unlock_and_cache_vault;
use crate::middleware::extract_session_token;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    50
}

#[derive(Serialize)]
pub struct AuditEntryResponse {
    pub sequence: u64,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub env: Option<String>,
    pub outcome: String,
}

pub async fn get_audit(
    State(state): State<AppState>,
    Path(vault_name): Path<String>,
    Query(query): Query<AuditQuery>,
    req: axum::extract::Request,
) -> Result<Json<Vec<AuditEntryResponse>>, WebError> {
    let token =
        extract_session_token(&req).ok_or_else(|| WebError::Unauthorized("no session".into()))?;

    // Ensure vault is unlocked
    let has_cached = state
        .sessions
        .with_session(&token, |s| s.vault_contexts.contains_key(&vault_name))
        .unwrap_or(false);

    if !has_cached {
        unlock_and_cache_vault(&state, &token, &vault_name)?;
    }

    let paths = VaultPaths::new(state.sigyn_home.clone());
    let audit_path = paths.audit_path(&vault_name);

    if !audit_path.exists() {
        return Ok(Json(Vec::new()));
    }

    let entries = state
        .sessions
        .with_session(&token, |session| {
            let ctx = session
                .vault_contexts
                .get(&vault_name)
                .ok_or_else(|| WebError::Internal("vault context missing".into()))?;

            let audit_cipher = derive_file_cipher_with_salt(
                ctx.vault_cipher.key_bytes(),
                b"sigyn-audit-v1",
                &ctx.manifest.vault_id,
            )
            .map_err(|e| WebError::Internal(format!("audit cipher error: {}", e)))?;

            let log = AuditLog::open(&audit_path, audit_cipher)
                .map_err(|e| WebError::Internal(format!("audit log open failed: {}", e)))?;

            let raw_entries = log
                .tail(query.limit)
                .map_err(|e| WebError::Internal(format!("audit tail failed: {}", e)))?;

            let items: Vec<AuditEntryResponse> = raw_entries
                .into_iter()
                .rev()
                .map(|entry| AuditEntryResponse {
                    sequence: entry.sequence,
                    timestamp: entry.timestamp.to_rfc3339(),
                    actor: entry.actor.to_hex(),
                    action: entry.action.short_name().to_string(),
                    env: entry.env,
                    outcome: format!("{:?}", entry.outcome),
                })
                .collect();

            Ok::<_, WebError>(items)
        })
        .ok_or_else(|| WebError::Unauthorized("session expired".into()))??;

    Ok(Json(entries))
}
