use sigyn_core::error::{Result, SigynError};
use sigyn_core::policy::AuditMode;

use crate::sync::git::GitSyncEngine;

/// Result of audit push enforcement.
#[derive(Debug)]
pub enum AuditPushOutcome {
    /// No push needed (offline mode or no remote configured).
    Skipped,
    /// Push succeeded.
    Pushed,
    /// Push failed in best-effort mode. Contains the error message.
    BestEffortFailed(String),
}

/// Enforce the vault's audit push policy after an audit entry has been appended locally.
///
/// - `Offline`: no-op (audit stays local until the user pushes).
/// - `Online`: stage + commit + push the audit data. If push fails, return `Err`.
/// - `BestEffort`: same as `Online`, but on failure return `Ok(BestEffortFailed)`.
///
/// If `deploy_key_bytes` is provided, the push uses that key for SSH auth instead
/// of the user's SSH agent. This allows audit push to work even when the user's
/// SSH key is locked or unavailable.
///
/// Push is only attempted when a git remote ("origin") is configured. Without a remote,
/// all modes return `Ok(Skipped)` — this prevents new vaults (no remote yet) from being
/// unusable.
pub fn enforce_audit_push(
    audit_mode: AuditMode,
    engine: &GitSyncEngine,
    commit_message: &str,
    deploy_key_bytes: Option<&[u8]>,
) -> Result<AuditPushOutcome> {
    match audit_mode {
        AuditMode::Offline => Ok(AuditPushOutcome::Skipped),
        AuditMode::Online | AuditMode::BestEffort => {
            if !engine.is_repo() || !engine.has_remote("origin") {
                return Ok(AuditPushOutcome::Skipped);
            }

            match try_push(engine, commit_message, deploy_key_bytes) {
                Ok(()) => Ok(AuditPushOutcome::Pushed),
                Err(e) if audit_mode == AuditMode::BestEffort => {
                    Ok(AuditPushOutcome::BestEffortFailed(e.to_string()))
                }
                Err(e) => Err(SigynError::AuditPushRequired(e.to_string())),
            }
        }
    }
}

fn try_push(
    engine: &GitSyncEngine,
    commit_message: &str,
    deploy_key_bytes: Option<&[u8]>,
) -> Result<()> {
    if engine.has_changes()? {
        engine.stage_all()?;
        engine.commit(commit_message)?;
    }
    match deploy_key_bytes {
        Some(key) => engine.push_with_deploy_key("origin", "main", key),
        None => engine.push("origin", "main"),
    }
}
