use std::path::PathBuf;

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
        self.vault_dir(name).join("audit.log.json")
    }

    pub fn witnesses_path(&self, name: &str) -> PathBuf {
        self.vault_dir(name).join("witnesses.json")
    }

    pub fn forks_path(&self, name: &str) -> PathBuf {
        self.vault_dir(name).join("forks.cbor")
    }

    pub fn lock_path(&self, name: &str) -> PathBuf {
        self.vault_dir(name).join(".lock")
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
    /// Scans all vaults and returns those whose manifest `org_path` matches or is a descendant.
    pub fn list_vaults_for_org(&self, org_path: &str) -> crate::Result<Vec<String>> {
        let all_vaults = self.list_vaults()?;
        let mut matching = Vec::new();
        for name in all_vaults {
            let manifest_path = self.manifest_path(&name);
            if let Ok(content) = std::fs::read_to_string(&manifest_path) {
                if let Ok(manifest) = super::manifest::VaultManifest::from_toml(&content) {
                    if let Some(ref vp) = manifest.org_path {
                        if vp == org_path || vp.starts_with(&format!("{}/", org_path)) {
                            matching.push(name);
                        }
                    }
                }
            }
        }
        Ok(matching)
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
