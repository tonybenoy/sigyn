use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use sigyn_engine::audit::AuditLog;
use sigyn_engine::crypto::sealed::derive_file_cipher_with_salt;
use sigyn_engine::policy::engine::{AccessAction, AccessRequest};
use sigyn_engine::policy::PolicyEngine;
use sigyn_engine::secrets::types::SecretValue;
use sigyn_engine::vault::env_file::{
    decrypt_env, encrypt_env, read_encrypted_env, write_encrypted_env,
};
use sigyn_engine::vault::VaultPaths;

use crate::error::WebError;
use crate::handlers::vault::unlock_and_cache_vault;
use crate::middleware::extract_session_token;
use crate::state::AppState;

#[derive(Serialize)]
pub struct SecretListItem {
    pub key: String,
    pub secret_type: String,
    pub version: u64,
    pub updated_at: String,
    pub updated_by: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Serialize)]
pub struct SecretDetail {
    pub key: String,
    pub value: String,
    pub secret_type: String,
    pub version: u64,
    pub created_at: String,
    pub updated_at: String,
    pub created_by: String,
    pub updated_by: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Deserialize)]
pub struct SetSecretRequest {
    pub key: String,
    pub value: String,
    #[serde(default = "default_secret_type")]
    pub secret_type: String,
}

fn default_secret_type() -> String {
    "string".into()
}

#[derive(Serialize)]
pub struct SecretResponse {
    pub ok: bool,
    pub message: String,
}

/// Validate an environment name from the URL path before it is used to build
/// filesystem paths (defense against traversal via encoded path segments).
fn validate_env_name(env_name: &str) -> Result<(), WebError> {
    sigyn_engine::vault::validate_name(env_name, "env")
        .map_err(|e| WebError::BadRequest(e.to_string()))
}

/// Ensure the vault is unlocked for this session, unlocking if needed.
fn ensure_vault_unlocked(state: &AppState, token: &str, vault_name: &str) -> Result<(), WebError> {
    let has_cached = state
        .sessions
        .with_session(token, |s| s.vault_contexts.contains_key(vault_name))
        .unwrap_or(false);

    if !has_cached {
        unlock_and_cache_vault(state, token, vault_name)?;
    }
    Ok(())
}

/// Check access using the policy engine.
fn check_access(
    state: &AppState,
    token: &str,
    vault_name: &str,
    env_name: &str,
    action: AccessAction,
    key: Option<String>,
) -> Result<(), WebError> {
    state
        .sessions
        .with_session(token, |session| {
            let ctx = session
                .vault_contexts
                .get(vault_name)
                .ok_or_else(|| WebError::Internal("vault context missing".into()))?;

            let engine = PolicyEngine::new(&ctx.policy, &ctx.manifest.owner);
            let request = AccessRequest {
                actor: session.fingerprint.clone(),
                action,
                env: env_name.to_string(),
                key,
                mfa_verified: false,
            };

            match engine.evaluate(&request) {
                Ok(sigyn_engine::policy::PolicyDecision::Allow) => Ok(()),
                Ok(sigyn_engine::policy::PolicyDecision::AllowWithWarning(_)) => Ok(()),
                Ok(sigyn_engine::policy::PolicyDecision::Deny(reason)) => {
                    Err(WebError::Forbidden(reason))
                }
                Ok(sigyn_engine::policy::PolicyDecision::RequiresMfa) => {
                    Err(WebError::Forbidden("MFA required".into()))
                }
                Err(e) => Err(WebError::Internal(format!(
                    "policy evaluation error: {}",
                    e
                ))),
            }
        })
        .ok_or_else(|| WebError::Unauthorized("session expired".into()))?
}

/// Append an audit log entry for a vault operation.
fn audit_log(
    state: &AppState,
    token: &str,
    vault_name: &str,
    env_name: Option<String>,
    action: sigyn_engine::audit::entry::AuditAction,
) -> Result<(), WebError> {
    state
        .sessions
        .with_session(token, |session| {
            let ctx = session
                .vault_contexts
                .get(vault_name)
                .ok_or_else(|| WebError::Internal("vault context missing".into()))?;

            let paths = VaultPaths::new(state.sigyn_home.clone());
            let audit_cipher = derive_file_cipher_with_salt(
                ctx.vault_cipher.key_bytes(),
                b"sigyn-audit-v1",
                &ctx.manifest.vault_id,
            )
            .map_err(|e| WebError::Internal(format!("audit cipher derivation failed: {}", e)))?;

            let mut log = AuditLog::open(&paths.audit_path(vault_name), audit_cipher)
                .map_err(|e| WebError::Internal(format!("audit log open failed: {}", e)))?;

            log.append(
                &session.fingerprint,
                action,
                env_name,
                sigyn_engine::audit::entry::AuditOutcome::Success,
                session.loaded_identity.signing_key(),
            )
            .map_err(|e| WebError::Internal(format!("audit log append failed: {}", e)))?;

            Ok::<_, WebError>(())
        })
        .ok_or_else(|| WebError::Unauthorized("session expired".into()))?
}

pub async fn list_secrets(
    State(state): State<AppState>,
    Path((vault_name, env_name)): Path<(String, String)>,
    req: axum::extract::Request,
) -> Result<Json<Vec<SecretListItem>>, WebError> {
    let token =
        extract_session_token(&req).ok_or_else(|| WebError::Unauthorized("no session".into()))?;

    validate_env_name(&env_name)?;
    ensure_vault_unlocked(&state, &token, &vault_name)?;
    check_access(
        &state,
        &token,
        &vault_name,
        &env_name,
        AccessAction::Read,
        None,
    )?;

    let paths = VaultPaths::new(state.sigyn_home.clone());
    let env_path = paths.env_path(&vault_name, &env_name);

    if !env_path.exists() {
        return Ok(Json(Vec::new()));
    }

    let entries = state
        .sessions
        .with_session(&token, |session| {
            let ctx = session
                .vault_contexts
                .get(&vault_name)
                .ok_or_else(|| WebError::Internal("vault context missing".into()))?;
            let cipher = ctx
                .env_ciphers
                .get(&env_name)
                .ok_or_else(|| WebError::Forbidden(format!("no access to env '{}'", env_name)))?;

            let encrypted = read_encrypted_env(&env_path)
                .map_err(|e| WebError::Internal(format!("failed to read env file: {}", e)))?;
            let plaintext = decrypt_env(&encrypted, cipher)
                .map_err(|e| WebError::Internal(format!("failed to decrypt env: {}", e)))?;

            let items: Vec<SecretListItem> = plaintext
                .entries
                .values()
                .map(|entry| SecretListItem {
                    key: entry.key.clone(),
                    secret_type: entry.value.type_name().to_string(),
                    version: entry.metadata.version,
                    updated_at: entry.metadata.updated_at.to_rfc3339(),
                    updated_by: entry.metadata.updated_by.to_hex(),
                    description: entry.metadata.description.clone(),
                    tags: entry.metadata.tags.clone(),
                })
                .collect();
            Ok::<_, WebError>(items)
        })
        .ok_or_else(|| WebError::Unauthorized("session expired".into()))??;

    // Audit the list operation. Reads are not failed on audit errors, but the
    // failure must not be silently discarded.
    if let Err(e) = audit_log(
        &state,
        &token,
        &vault_name,
        Some(env_name.clone()),
        sigyn_engine::audit::entry::AuditAction::SecretsListed {
            env: env_name.clone(),
        },
    ) {
        eprintln!(
            "sigyn-web: WARNING: failed to write audit entry for secrets list (vault '{}', env '{}'): {:?}",
            vault_name, env_name, e
        );
    }

    Ok(Json(entries))
}

pub async fn get_secret(
    State(state): State<AppState>,
    Path((vault_name, env_name, key)): Path<(String, String, String)>,
    req: axum::extract::Request,
) -> Result<Json<SecretDetail>, WebError> {
    let token =
        extract_session_token(&req).ok_or_else(|| WebError::Unauthorized("no session".into()))?;

    validate_env_name(&env_name)?;
    ensure_vault_unlocked(&state, &token, &vault_name)?;
    check_access(
        &state,
        &token,
        &vault_name,
        &env_name,
        AccessAction::Read,
        Some(key.clone()),
    )?;

    let paths = VaultPaths::new(state.sigyn_home.clone());
    let env_path = paths.env_path(&vault_name, &env_name);

    let detail = state
        .sessions
        .with_session(&token, |session| {
            let ctx = session
                .vault_contexts
                .get(&vault_name)
                .ok_or_else(|| WebError::Internal("vault context missing".into()))?;
            let cipher = ctx
                .env_ciphers
                .get(&env_name)
                .ok_or_else(|| WebError::Forbidden(format!("no access to env '{}'", env_name)))?;

            let encrypted = read_encrypted_env(&env_path)
                .map_err(|e| WebError::Internal(format!("failed to read env file: {}", e)))?;
            let plaintext = decrypt_env(&encrypted, cipher)
                .map_err(|e| WebError::Internal(format!("failed to decrypt env: {}", e)))?;

            let entry = plaintext
                .get(&key)
                .ok_or_else(|| WebError::NotFound(format!("secret '{}' not found", key)))?;

            Ok::<_, WebError>(SecretDetail {
                key: entry.key.clone(),
                value: entry.value.display_value(true),
                secret_type: entry.value.type_name().to_string(),
                version: entry.metadata.version,
                created_at: entry.metadata.created_at.to_rfc3339(),
                updated_at: entry.metadata.updated_at.to_rfc3339(),
                created_by: entry.metadata.created_by.to_hex(),
                updated_by: entry.metadata.updated_by.to_hex(),
                description: entry.metadata.description.clone(),
                tags: entry.metadata.tags.clone(),
            })
        })
        .ok_or_else(|| WebError::Unauthorized("session expired".into()))??;

    // Audit the read. Reads are not failed on audit errors, but the failure
    // must not be silently discarded.
    if let Err(e) = audit_log(
        &state,
        &token,
        &vault_name,
        Some(env_name.clone()),
        sigyn_engine::audit::entry::AuditAction::SecretRead { key: key.clone() },
    ) {
        eprintln!(
            "sigyn-web: WARNING: failed to write audit entry for secret read (vault '{}', env '{}', key '{}'): {:?}",
            vault_name, env_name, key, e
        );
    }

    Ok(Json(detail))
}

pub async fn set_secret(
    State(state): State<AppState>,
    Path((vault_name, env_name)): Path<(String, String)>,
    req: axum::extract::Request,
) -> Result<Json<SecretResponse>, WebError> {
    let token =
        extract_session_token(&req).ok_or_else(|| WebError::Unauthorized("no session".into()))?;

    // Parse body manually since we already extracted the request
    let body = axum::body::to_bytes(req.into_body(), 1024 * 1024)
        .await
        .map_err(|e| WebError::BadRequest(format!("failed to read body: {}", e)))?;
    let set_req: SetSecretRequest = serde_json::from_slice(&body)
        .map_err(|e| WebError::BadRequest(format!("invalid JSON: {}", e)))?;

    validate_env_name(&env_name)?;
    ensure_vault_unlocked(&state, &token, &vault_name)?;
    check_access(
        &state,
        &token,
        &vault_name,
        &env_name,
        AccessAction::Write,
        Some(set_req.key.clone()),
    )?;

    let paths = VaultPaths::new(state.sigyn_home.clone());
    let env_path = paths.env_path(&vault_name, &env_name);

    let key_clone = set_req.key.clone();

    // Validate the value before auditing so a malformed request doesn't
    // produce a spurious audit entry.
    let value = match set_req.secret_type.as_str() {
        "multiline" => SecretValue::Multiline(set_req.value),
        "json" => {
            let v: serde_json::Value = serde_json::from_str(&set_req.value)
                .map_err(|e| WebError::BadRequest(format!("invalid JSON value: {}", e)))?;
            SecretValue::Json(v)
        }
        _ => SecretValue::String(set_req.value),
    };

    // Audit before persisting the mutation (matches the CLI ordering). A
    // failed audit append fails the whole operation: no unaudited writes.
    audit_log(
        &state,
        &token,
        &vault_name,
        Some(env_name.clone()),
        sigyn_engine::audit::entry::AuditAction::SecretWritten {
            key: key_clone.clone(),
        },
    )?;

    state
        .sessions
        .with_session(&token, |session| {
            let ctx = session
                .vault_contexts
                .get(&vault_name)
                .ok_or_else(|| WebError::Internal("vault context missing".into()))?;
            let cipher = ctx
                .env_ciphers
                .get(&env_name)
                .ok_or_else(|| WebError::Forbidden(format!("no access to env '{}'", env_name)))?;

            // Load existing env or create new
            let mut plaintext = if env_path.exists() {
                let encrypted = read_encrypted_env(&env_path)
                    .map_err(|e| WebError::Internal(format!("failed to read env: {}", e)))?;
                decrypt_env(&encrypted, cipher)
                    .map_err(|e| WebError::Internal(format!("failed to decrypt env: {}", e)))?
            } else {
                sigyn_engine::vault::PlaintextEnv::new()
            };

            plaintext.set(set_req.key, value, &session.fingerprint);

            let encrypted = encrypt_env(&plaintext, cipher, &env_name)
                .map_err(|e| WebError::Internal(format!("failed to encrypt env: {}", e)))?;
            write_encrypted_env(&env_path, &encrypted)
                .map_err(|e| WebError::Internal(format!("failed to write env: {}", e)))?;

            Ok::<_, WebError>(())
        })
        .ok_or_else(|| WebError::Unauthorized("session expired".into()))??;

    Ok(Json(SecretResponse {
        ok: true,
        message: format!("secret '{}' saved", key_clone),
    }))
}

pub async fn delete_secret(
    State(state): State<AppState>,
    Path((vault_name, env_name, key)): Path<(String, String, String)>,
    req: axum::extract::Request,
) -> Result<Json<SecretResponse>, WebError> {
    let token =
        extract_session_token(&req).ok_or_else(|| WebError::Unauthorized("no session".into()))?;

    validate_env_name(&env_name)?;
    ensure_vault_unlocked(&state, &token, &vault_name)?;
    check_access(
        &state,
        &token,
        &vault_name,
        &env_name,
        AccessAction::Delete,
        Some(key.clone()),
    )?;

    let paths = VaultPaths::new(state.sigyn_home.clone());
    let env_path = paths.env_path(&vault_name, &env_name);

    if !env_path.exists() {
        return Err(WebError::NotFound(format!("env '{}' not found", env_name)));
    }

    // Check the secret exists before auditing so a miss doesn't produce a
    // spurious audit entry.
    let exists = state
        .sessions
        .with_session(&token, |session| {
            let ctx = session
                .vault_contexts
                .get(&vault_name)
                .ok_or_else(|| WebError::Internal("vault context missing".into()))?;
            let cipher = ctx
                .env_ciphers
                .get(&env_name)
                .ok_or_else(|| WebError::Forbidden(format!("no access to env '{}'", env_name)))?;

            let encrypted = read_encrypted_env(&env_path)
                .map_err(|e| WebError::Internal(format!("failed to read env: {}", e)))?;
            let plaintext = decrypt_env(&encrypted, cipher)
                .map_err(|e| WebError::Internal(format!("failed to decrypt env: {}", e)))?;

            Ok::<_, WebError>(plaintext.get(&key).is_some())
        })
        .ok_or_else(|| WebError::Unauthorized("session expired".into()))??;

    if !exists {
        return Err(WebError::NotFound(format!("secret '{}' not found", key)));
    }

    // Audit before persisting the mutation (matches the CLI ordering). A
    // failed audit append fails the whole operation: no unaudited deletes.
    audit_log(
        &state,
        &token,
        &vault_name,
        Some(env_name.clone()),
        sigyn_engine::audit::entry::AuditAction::SecretDeleted { key: key.clone() },
    )?;

    let removed = state
        .sessions
        .with_session(&token, |session| {
            let ctx = session
                .vault_contexts
                .get(&vault_name)
                .ok_or_else(|| WebError::Internal("vault context missing".into()))?;
            let cipher = ctx
                .env_ciphers
                .get(&env_name)
                .ok_or_else(|| WebError::Forbidden(format!("no access to env '{}'", env_name)))?;

            let encrypted = read_encrypted_env(&env_path)
                .map_err(|e| WebError::Internal(format!("failed to read env: {}", e)))?;
            let mut plaintext = decrypt_env(&encrypted, cipher)
                .map_err(|e| WebError::Internal(format!("failed to decrypt env: {}", e)))?;

            let removed = plaintext.remove(&key).is_some();
            if removed {
                let encrypted = encrypt_env(&plaintext, cipher, &env_name)
                    .map_err(|e| WebError::Internal(format!("failed to encrypt env: {}", e)))?;
                write_encrypted_env(&env_path, &encrypted)
                    .map_err(|e| WebError::Internal(format!("failed to write env: {}", e)))?;
            }

            Ok::<_, WebError>(removed)
        })
        .ok_or_else(|| WebError::Unauthorized("session expired".into()))??;

    if !removed {
        return Err(WebError::NotFound(format!("secret '{}' not found", key)));
    }

    Ok(Json(SecretResponse {
        ok: true,
        message: format!("secret '{}' deleted", key),
    }))
}
