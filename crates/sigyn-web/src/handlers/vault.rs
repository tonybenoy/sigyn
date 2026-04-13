use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;
use std::collections::BTreeMap;

use sigyn_engine::crypto::envelope;
use sigyn_engine::crypto::keys::KeyFingerprint;
use sigyn_engine::crypto::vault_cipher::VaultCipher;
use sigyn_engine::identity::keygen::IdentityStore;
use sigyn_engine::policy::storage::VaultPolicy;
use sigyn_engine::policy::storage::VaultPolicyExt;
use sigyn_engine::vault::VaultPaths;

use crate::error::WebError;
use crate::middleware::extract_session_token;
use crate::session::CachedVaultContext;
use crate::state::AppState;

#[derive(Serialize)]
pub struct VaultListItem {
    pub name: String,
}

#[derive(Serialize)]
pub struct VaultInfo {
    pub name: String,
    pub vault_id: String,
    pub owner: String,
    pub environments: Vec<String>,
    pub description: Option<String>,
    pub members: Vec<MemberSummary>,
}

#[derive(Serialize)]
pub struct MemberSummary {
    pub fingerprint: String,
    pub role: String,
    pub allowed_envs: Vec<String>,
}

pub async fn list_vaults(
    State(state): State<AppState>,
) -> Result<Json<Vec<VaultListItem>>, WebError> {
    let paths = VaultPaths::new(state.sigyn_home.clone());
    let vaults = paths
        .list_vaults()
        .map_err(|e| WebError::Internal(format!("failed to list vaults: {}", e)))?;

    let result: Vec<VaultListItem> = vaults
        .into_iter()
        .map(|name| VaultListItem { name })
        .collect();

    Ok(Json(result))
}

pub async fn get_vault(
    State(state): State<AppState>,
    Path(vault_name): Path<String>,
    req: axum::extract::Request,
) -> Result<Json<VaultInfo>, WebError> {
    let token =
        extract_session_token(&req).ok_or_else(|| WebError::Unauthorized("no session".into()))?;

    // Check if we already have a cached context for this vault
    let has_cached = state
        .sessions
        .with_session(&token, |s| s.vault_contexts.contains_key(&vault_name))
        .unwrap_or(false);

    if !has_cached {
        // Unlock the vault and cache the context
        unlock_and_cache_vault(&state, &token, &vault_name)?;
    }

    // Read from the cached context
    let info = state
        .sessions
        .with_session(&token, |session| {
            let ctx = session.vault_contexts.get(&vault_name).unwrap();
            let members: Vec<MemberSummary> = ctx
                .policy
                .members
                .values()
                .map(|m| MemberSummary {
                    fingerprint: m.fingerprint.to_hex(),
                    role: format!("{:?}", m.role),
                    allowed_envs: m.allowed_envs.clone(),
                })
                .collect();

            VaultInfo {
                name: ctx.manifest.name.clone(),
                vault_id: ctx.manifest.vault_id.to_string(),
                owner: ctx.manifest.owner.to_hex(),
                environments: ctx.manifest.environments.clone(),
                description: ctx.manifest.description.clone(),
                members,
            }
        })
        .ok_or_else(|| WebError::Unauthorized("session expired".into()))?;

    Ok(Json(info))
}

/// Unlock a vault using the session's loaded identity and cache the result.
/// This replicates the core logic from CLI's `unlock_vault()` but without
/// CLI-specific concerns (config resolution, terminal output, project config).
pub fn unlock_and_cache_vault(
    state: &AppState,
    token: &str,
    vault_name: &str,
) -> Result<(), WebError> {
    let paths = VaultPaths::new(state.sigyn_home.clone());

    // Verify no symlinks
    paths
        .safe_vault_dir(vault_name)
        .map_err(|e| WebError::BadRequest(format!("vault path security check failed: {}", e)))?;

    // Read raw vault files
    let manifest_data = std::fs::read(paths.manifest_path(vault_name))
        .map_err(|_| WebError::NotFound(format!("vault '{}' not found", vault_name)))?;
    let header_bytes = std::fs::read(paths.members_path(vault_name))
        .map_err(|e| WebError::Internal(format!("failed to read vault members: {}", e)))?;

    // Extract vault_id from header (unverified bootstrap)
    let header_preview = envelope::extract_header_unverified(&header_bytes)
        .map_err(|e| WebError::Internal(format!("failed to decode header: {}", e)))?;
    let vault_id = header_preview
        .vault_id
        .ok_or_else(|| WebError::Internal("vault header missing vault_id".into()))?;

    // Get encryption key from session to unseal
    let (vault_key_bytes, env_key_map, loaded_identity_signing_pubkey, loaded_identity_fingerprint) =
        state
            .sessions
            .with_session(token, |session| {
                let (vk, ek) = envelope::unseal_header(
                    &header_preview,
                    session.loaded_identity.encryption_key(),
                    vault_id,
                    &[],
                )
                .map_err(|_| {
                    WebError::Forbidden(format!(
                        "cannot unseal vault '{}' (not a member or wrong key)",
                        vault_name
                    ))
                })?;
                Ok::<_, WebError>((
                    vk,
                    ek,
                    session.loaded_identity.identity.signing_pubkey.clone(),
                    session.loaded_identity.identity.fingerprint.clone(),
                ))
            })
            .ok_or_else(|| WebError::Unauthorized("session expired".into()))??;

    let vault_cipher = VaultCipher::new(vault_key_bytes);

    // Decrypt manifest
    let manifest = sigyn_engine::vault::VaultManifest::from_sealed_bytes(
        &vault_cipher,
        &manifest_data,
        vault_id,
    )
    .map_err(|e| WebError::Internal(format!("failed to decrypt manifest: {}", e)))?;

    // Verify header signature against known identities
    let store = IdentityStore::new(state.sigyn_home.clone());
    let identities = store
        .list()
        .map_err(|e| WebError::Internal(format!("failed to list identities: {}", e)))?;

    let mut candidates: Vec<(
        KeyFingerprint,
        sigyn_engine::crypto::keys::VerifyingKeyWrapper,
    )> = Vec::new();

    // Owner first
    if let Some(owner_id) = identities
        .iter()
        .find(|id| id.fingerprint == manifest.owner)
    {
        candidates.push((
            owner_id.fingerprint.clone(),
            owner_id.signing_pubkey.clone(),
        ));
    }
    // Current user
    if !candidates
        .iter()
        .any(|(fp, _)| *fp == loaded_identity_fingerprint)
    {
        candidates.push((
            loaded_identity_fingerprint.clone(),
            loaded_identity_signing_pubkey.clone(),
        ));
    }
    // All other known identities
    for id in &identities {
        if !candidates.iter().any(|(fp, _)| *fp == id.fingerprint) {
            candidates.push((id.fingerprint.clone(), id.signing_pubkey.clone()));
        }
    }

    let header_signer_fp = candidates
        .iter()
        .find(|(_, key)| envelope::verify_and_load_header(&header_bytes, vault_id, key).is_ok())
        .map(|(fp, _)| fp.clone())
        .ok_or_else(|| {
            WebError::Forbidden("header signature verification failed: no known signer".into())
        })?;

    // Load and verify policy
    let policy_candidates: Vec<sigyn_engine::crypto::keys::VerifyingKeyWrapper> = {
        let mut pc = Vec::new();
        // Header signer first
        if let Some(signer) = identities
            .iter()
            .find(|id| id.fingerprint == header_signer_fp)
        {
            pc.push(signer.signing_pubkey.clone());
        } else if loaded_identity_fingerprint == header_signer_fp {
            pc.push(loaded_identity_signing_pubkey.clone());
        }
        // Owner if different
        if header_signer_fp != manifest.owner {
            if let Some(owner) = identities
                .iter()
                .find(|id| id.fingerprint == manifest.owner)
            {
                pc.push(owner.signing_pubkey.clone());
            }
        }
        // All others
        for id in &identities {
            if !pc
                .iter()
                .any(|k| k.to_bytes() == id.signing_pubkey.to_bytes())
            {
                pc.push(id.signing_pubkey.clone());
            }
        }
        if !pc
            .iter()
            .any(|k| k.to_bytes() == loaded_identity_signing_pubkey.to_bytes())
        {
            pc.push(loaded_identity_signing_pubkey);
        }
        pc
    };

    let policy = policy_candidates
        .iter()
        .find_map(|key| {
            VaultPolicy::load_signed(
                &paths.policy_path(vault_name),
                &vault_cipher,
                key,
                &manifest.vault_id,
            )
            .ok()
        })
        .ok_or_else(|| WebError::Forbidden("policy signature verification failed".into()))?;

    // Verify header signer is authorized (owner or admin+)
    if header_signer_fp != manifest.owner {
        match policy.get_member(&header_signer_fp) {
            Some(member) if member.role.can_manage_policy() => {}
            _ => {
                return Err(WebError::Forbidden(
                    "header signed by unauthorized identity".into(),
                ));
            }
        }
    }

    // Build env ciphers map
    let mut env_ciphers = BTreeMap::new();
    for (ename, ekey) in &env_key_map {
        env_ciphers.insert(ename.clone(), VaultCipher::new(*ekey));
    }

    let cached = CachedVaultContext {
        vault_cipher,
        env_ciphers,
        manifest,
        policy,
        header: header_preview,
    };

    // Store in session
    state
        .sessions
        .with_session_mut(token, |session| {
            session
                .vault_contexts
                .insert(vault_name.to_string(), cached);
        })
        .ok_or_else(|| WebError::Unauthorized("session expired".into()))?;

    Ok(())
}
