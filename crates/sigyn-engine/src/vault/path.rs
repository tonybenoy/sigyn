use std::path::{Path, PathBuf};

use sigyn_core::crypto::sealed::{derive_file_cipher, is_sealed, sealed_decrypt, sealed_encrypt};
use sigyn_core::error::SigynError;

const ORG_LINK_HKDF_CONTEXT: &[u8] = b"sigyn-org-link-v1";
const ORG_LINK_AAD: &[u8] = b".org_link";

/// Validate a vault or environment name.
///
/// Rejects: empty, >64 chars, starts with `.`, contains `/` `\` `..` or NUL,
/// and any character outside `[a-zA-Z0-9\-_]`.
pub fn validate_name(name: &str, kind: &str) -> crate::Result<()> {
    if name.is_empty() {
        return Err(SigynError::InvalidName(format!(
            "{} name cannot be empty",
            kind
        )));
    }
    // Reject NUL bytes early (prevents C-string truncation attacks)
    if name.bytes().any(|b| b == 0) {
        return Err(SigynError::InvalidName(format!(
            "{} name must not contain NUL bytes",
            kind
        )));
    }
    if name.len() > 64 {
        return Err(SigynError::InvalidName(format!(
            "{} name exceeds 64 characters",
            kind
        )));
    }
    if name.starts_with('.') {
        return Err(SigynError::InvalidName(format!(
            "{} name cannot start with '.'",
            kind
        )));
    }
    if name.contains("..") {
        return Err(SigynError::InvalidName(format!(
            "{} name cannot contain '..'",
            kind
        )));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(SigynError::InvalidName(format!(
            "{} name may only contain [a-zA-Z0-9-_]",
            kind
        )));
    }
    Ok(())
}

pub struct VaultPaths {
    base: PathBuf,
}

impl VaultPaths {
    pub fn new(base: PathBuf) -> Self {
        Self { base }
    }

    pub fn vault_dir(&self, name: &str) -> PathBuf {
        self.base.join("vaults").join(name)
    }

    /// Return the vault directory after verifying no symlinks exist in the path.
    /// This prevents symlink-based attacks where a vault directory is replaced
    /// with a symlink pointing to an attacker-controlled location.
    pub fn safe_vault_dir(&self, name: &str) -> crate::Result<PathBuf> {
        let dir = self.vault_dir(name);
        crate::io::reject_symlinks_in_vault_path(&dir)?;
        Ok(dir)
    }

    pub fn manifest_path(&self, name: &str) -> PathBuf {
        self.vault_dir(name).join("vault.toml")
    }

    pub fn members_path(&self, name: &str) -> PathBuf {
        self.vault_dir(name).join("members.cbor")
    }

    pub fn policy_path(&self, name: &str) -> PathBuf {
        self.vault_dir(name).join("policy.cbor")
    }

    pub fn env_dir(&self, name: &str) -> PathBuf {
        self.vault_dir(name).join("envs")
    }

    pub fn env_path(&self, vault_name: &str, env_name: &str) -> PathBuf {
        self.env_dir(vault_name).join(format!("{}.vault", env_name))
    }

    pub fn audit_path(&self, name: &str) -> PathBuf {
        match self.detect_layout(name) {
            VaultLayout::SingleRepo => self.vault_dir(name).join("audit.log.json"),
            VaultLayout::SplitRepo => self.audit_repo_dir(name).join("audit.log.json"),
        }
    }

    pub fn witnesses_path(&self, name: &str) -> PathBuf {
        match self.detect_layout(name) {
            VaultLayout::SingleRepo => self.vault_dir(name).join("witnesses.json"),
            VaultLayout::SplitRepo => self.audit_repo_dir(name).join("witnesses.json"),
        }
    }

    /// The audit sub-repo directory for split-repo layouts.
    pub fn audit_repo_dir(&self, name: &str) -> PathBuf {
        self.vault_dir(name).join("audit")
    }

    /// Detect whether this vault uses a single repo or a split (vault + audit) layout.
    pub fn detect_layout(&self, name: &str) -> VaultLayout {
        let audit_dir = self.vault_dir(name).join("audit");
        if audit_dir.is_dir() && audit_dir.join(".git").exists() {
            VaultLayout::SplitRepo
        } else {
            VaultLayout::SingleRepo
        }
    }

    pub fn pending_transfer_path(&self, name: &str) -> PathBuf {
        self.vault_dir(name).join("pending_transfer.cbor")
    }

    pub fn forks_path(&self, name: &str) -> PathBuf {
        self.vault_dir(name).join("forks.cbor")
    }

    pub fn lock_path(&self, name: &str) -> PathBuf {
        self.vault_dir(name).join(".lock")
    }

    pub fn checkpoint_path(&self, name: &str) -> PathBuf {
        self.vault_dir(name).join("audit.checkpoint")
    }

    pub fn list_vaults(&self) -> crate::Result<Vec<String>> {
        let vaults_dir = self.base.join("vaults");
        if !vaults_dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&vaults_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    let manifest = entry.path().join("vault.toml");
                    if manifest.exists() {
                        names.push(name.to_string());
                    }
                }
            }
        }
        names.sort();
        Ok(names)
    }

    /// List vaults that belong to a given org path.
    ///
    /// Since vault manifests are encrypted, this method checks for an `org_link` metadata
    /// file in the vault directory. This file is written when a vault is created with --org
    /// or attached via `vault attach`. The org_link file is device-key encrypted.
    pub fn list_vaults_for_org(
        &self,
        org_path: &str,
        device_key: Option<&[u8; 32]>,
    ) -> crate::Result<Vec<String>> {
        let all_vaults = self.list_vaults()?;
        let mut matching = Vec::new();
        for name in all_vaults {
            let link_path = self.vault_dir(&name).join(".org_link");
            if let Some(linked_org) = read_org_link(&link_path, device_key) {
                if linked_org == org_path || linked_org.starts_with(&format!("{}/", org_path)) {
                    matching.push(name);
                }
            }
        }
        Ok(matching)
    }
}

/// Whether the vault uses a single git repo or separate vault + audit repos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultLayout {
    SingleRepo,
    SplitRepo,
}

/// Write an encrypted `.org_link` file using the device key.
pub fn write_org_link(path: &Path, org_path: &str, device_key: &[u8; 32]) -> crate::Result<()> {
    let cipher = derive_file_cipher(device_key, ORG_LINK_HKDF_CONTEXT)?;
    let sealed = sealed_encrypt(&cipher, org_path.as_bytes(), ORG_LINK_AAD)?;
    crate::io::atomic_write(path, &sealed)?;
    Ok(())
}

/// Read an `.org_link` file. Handles both encrypted (new) and plaintext (legacy) formats.
pub fn read_org_link(path: &Path, device_key: Option<&[u8; 32]>) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    if is_sealed(&data) {
        let key = device_key?;
        let cipher = derive_file_cipher(key, ORG_LINK_HKDF_CONTEXT).ok()?;
        let plaintext = sealed_decrypt(&cipher, &data, ORG_LINK_AAD).ok()?;
        String::from_utf8(plaintext).ok()
    } else {
        // Legacy plaintext format
        Some(String::from_utf8_lossy(&data).trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_dir() {
        let paths = VaultPaths::new(PathBuf::from("/home/user/.sigyn"));
        assert_eq!(
            paths.vault_dir("myapp"),
            PathBuf::from("/home/user/.sigyn/vaults/myapp")
        );
    }

    #[test]
    fn test_manifest_path() {
        let paths = VaultPaths::new(PathBuf::from("/base"));
        assert_eq!(
            paths.manifest_path("v1"),
            PathBuf::from("/base/vaults/v1/vault.toml")
        );
    }

    #[test]
    fn test_members_path() {
        let paths = VaultPaths::new(PathBuf::from("/base"));
        assert_eq!(
            paths.members_path("v1"),
            PathBuf::from("/base/vaults/v1/members.cbor")
        );
    }

    #[test]
    fn test_policy_path() {
        let paths = VaultPaths::new(PathBuf::from("/base"));
        assert_eq!(
            paths.policy_path("v1"),
            PathBuf::from("/base/vaults/v1/policy.cbor")
        );
    }

    #[test]
    fn test_env_dir() {
        let paths = VaultPaths::new(PathBuf::from("/base"));
        assert_eq!(paths.env_dir("v1"), PathBuf::from("/base/vaults/v1/envs"));
    }

    #[test]
    fn test_env_path() {
        let paths = VaultPaths::new(PathBuf::from("/base"));
        assert_eq!(
            paths.env_path("v1", "dev"),
            PathBuf::from("/base/vaults/v1/envs/dev.vault")
        );
    }

    #[test]
    fn test_audit_path() {
        let paths = VaultPaths::new(PathBuf::from("/base"));
        assert_eq!(
            paths.audit_path("v1"),
            PathBuf::from("/base/vaults/v1/audit.log.json")
        );
    }

    #[test]
    fn test_witnesses_path() {
        let paths = VaultPaths::new(PathBuf::from("/base"));
        assert_eq!(
            paths.witnesses_path("v1"),
            PathBuf::from("/base/vaults/v1/witnesses.json")
        );
    }

    #[test]
    fn test_forks_path() {
        let paths = VaultPaths::new(PathBuf::from("/base"));
        assert_eq!(
            paths.forks_path("v1"),
            PathBuf::from("/base/vaults/v1/forks.cbor")
        );
    }

    #[test]
    fn test_lock_path() {
        let paths = VaultPaths::new(PathBuf::from("/base"));
        assert_eq!(
            paths.lock_path("v1"),
            PathBuf::from("/base/vaults/v1/.lock")
        );
    }

    #[test]
    fn test_validate_name_valid() {
        assert!(validate_name("my-vault_1", "vault").is_ok());
        assert!(validate_name("a", "vault").is_ok());
        assert!(validate_name("A-B_c-123", "env").is_ok());
    }

    #[test]
    fn test_validate_name_empty() {
        assert!(validate_name("", "vault").is_err());
    }

    #[test]
    fn test_validate_name_too_long() {
        let long = "a".repeat(65);
        assert!(validate_name(&long, "vault").is_err());
        let exact = "a".repeat(64);
        assert!(validate_name(&exact, "vault").is_ok());
    }

    #[test]
    fn test_validate_name_dot_prefix() {
        assert!(validate_name(".hidden", "vault").is_err());
    }

    #[test]
    fn test_validate_name_path_traversal() {
        assert!(validate_name("../etc", "vault").is_err());
    }

    #[test]
    fn test_validate_name_slash() {
        assert!(validate_name("foo/bar", "vault").is_err());
        assert!(validate_name("foo\\bar", "vault").is_err());
    }

    #[test]
    fn test_validate_name_special_chars() {
        assert!(validate_name("foo bar", "vault").is_err());
        assert!(validate_name("foo.bar", "vault").is_err());
    }

    #[test]
    fn test_list_vaults_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().to_path_buf());
        assert_eq!(paths.list_vaults().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn test_list_vaults_with_manifests() {
        let dir = tempfile::tempdir().unwrap();
        let vaults = dir.path().join("vaults");

        // Create two valid vaults with vault.toml
        std::fs::create_dir_all(vaults.join("beta")).unwrap();
        std::fs::write(vaults.join("beta/vault.toml"), "name = \"beta\"").unwrap();
        std::fs::create_dir_all(vaults.join("alpha")).unwrap();
        std::fs::write(vaults.join("alpha/vault.toml"), "name = \"alpha\"").unwrap();

        // Create a dir without vault.toml (should be ignored)
        std::fs::create_dir_all(vaults.join("orphan")).unwrap();

        let paths = VaultPaths::new(dir.path().to_path_buf());
        let result = paths.list_vaults().unwrap();
        assert_eq!(result, vec!["alpha", "beta"]);
    }
}
