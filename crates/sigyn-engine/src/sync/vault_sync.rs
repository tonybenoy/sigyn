use crate::error::{Result, SigynError};
use crate::vault::path::{VaultLayout, VaultPaths};

use super::git::{GitSyncEngine, PullResult};

/// Coordinates sync operations across one or two git repos (vault + optional audit).
pub struct VaultSyncEngine {
    vault_engine: GitSyncEngine,
    audit_engine: Option<GitSyncEngine>,
    layout: VaultLayout,
}

impl VaultSyncEngine {
    /// Create a sync engine for the given vault, auto-detecting the layout.
    pub fn new(paths: &VaultPaths, vault_name: &str) -> Self {
        let layout = paths.detect_layout(vault_name);
        let vault_engine = GitSyncEngine::new(paths.vault_dir(vault_name));
        let audit_engine = match layout {
            VaultLayout::SplitRepo => Some(GitSyncEngine::new(paths.audit_repo_dir(vault_name))),
            VaultLayout::SingleRepo => None,
        };
        Self {
            vault_engine,
            audit_engine,
            layout,
        }
    }

    pub fn layout(&self) -> VaultLayout {
        self.layout
    }

    pub fn vault_engine(&self) -> &GitSyncEngine {
        &self.vault_engine
    }

    pub fn audit_engine(&self) -> Option<&GitSyncEngine> {
        self.audit_engine.as_ref()
    }

    /// Pull both repos with rollback protection.
    pub fn pull(
        &self,
        remote: &str,
        branch: &str,
        vault_checkpoint: Option<&str>,
        audit_checkpoint: Option<&str>,
    ) -> Result<PullResult> {
        let vault_result =
            self.vault_engine
                .pull_with_rollback_check(remote, branch, vault_checkpoint)?;

        if let Some(ref audit) = self.audit_engine {
            match audit.pull_with_rollback_check(remote, branch, audit_checkpoint) {
                Ok(_) => {}
                Err(SigynError::RollbackDetected {
                    remote: r,
                    local: l,
                }) => {
                    return Err(SigynError::RollbackDetected {
                        remote: format!("audit:{}", r),
                        local: format!("audit:{}", l),
                    });
                }
                Err(e) => return Err(e),
            }
        }

        Ok(vault_result)
    }

    /// Push both repos.
    pub fn push(&self, remote: &str, branch: &str) -> Result<()> {
        self.vault_engine.push(remote, branch)?;
        if let Some(ref audit) = self.audit_engine {
            audit.push(remote, branch)?;
        }
        Ok(())
    }

    /// Get HEAD OIDs for both repos.
    pub fn head_oids(&self) -> Result<(Option<String>, Option<String>)> {
        let vault_oid = self.vault_engine.head_oid()?;
        let audit_oid = match &self.audit_engine {
            Some(e) => e.head_oid()?,
            None => None,
        };
        Ok((vault_oid, audit_oid))
    }

    /// Check if either repo has uncommitted changes.
    pub fn has_changes(&self) -> Result<(bool, bool)> {
        let vault_changes = self.vault_engine.has_changes()?;
        let audit_changes = match &self.audit_engine {
            Some(e) => e.has_changes()?,
            None => false,
        };
        Ok((vault_changes, audit_changes))
    }
}

/// Initialize an audit sub-repo for a split-repo vault layout.
pub fn init_audit_repo(vault_dir: &std::path::Path) -> Result<()> {
    let audit_dir = vault_dir.join("audit");
    std::fs::create_dir_all(&audit_dir)
        .map_err(|e| SigynError::GitError(format!("failed to create audit dir: {}", e)))?;

    let engine = GitSyncEngine::new(audit_dir.clone());
    engine.init()?;

    // Add audit/ to the vault's .gitignore so it's not tracked by the vault repo
    let gitignore_path = vault_dir.join(".gitignore");
    let mut content = if gitignore_path.exists() {
        std::fs::read_to_string(&gitignore_path).unwrap_or_default()
    } else {
        String::new()
    };
    if !content.contains("audit/") {
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str("audit/\n");
        std::fs::write(&gitignore_path, content)
            .map_err(|e| SigynError::GitError(format!("failed to write .gitignore: {}", e)))?;
    }

    Ok(())
}
