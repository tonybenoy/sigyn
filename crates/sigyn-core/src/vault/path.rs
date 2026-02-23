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
}
