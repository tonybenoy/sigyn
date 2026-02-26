use std::fs::{File, OpenOptions};
use std::path::Path;

use fd_lock::RwLock;

use crate::error::{Result, SigynError};

pub struct VaultLock {
    _lock: RwLock<File>,
}

impl VaultLock {
    pub fn acquire(lock_path: &Path) -> Result<Self> {
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|e| SigynError::LockFailed(e.to_string()))?;

        // Restrict lock file permissions to owner-only (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }

        let mut lock = RwLock::new(file);
        let _ = lock.try_write().map_err(|_| {
            SigynError::LockFailed(format!(
                "vault is locked by another process ({}). If stale, delete the lock file or use force-unlock.",
                lock_path.display()
            ))
        })?;

        Ok(Self { _lock: lock })
    }

    /// Force-acquire the lock by removing any stale lock file atomically.
    /// This avoids the TOCTOU of checking existence then removing — just
    /// attempt removal unconditionally (ENOENT is fine).
    pub fn force_acquire(lock_path: &Path) -> Result<Self> {
        // Atomically remove the stale lock file; ignore "not found" errors
        match std::fs::remove_file(lock_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Self::acquire(lock_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_vault_lock_acquisition() {
        let tmp = tempdir().unwrap();
        let lock_path = tmp.path().join("vault.lock");

        // 1. Acquire lock
        {
            let _lock1 = VaultLock::acquire(&lock_path).unwrap();
            assert!(lock_path.exists());
        }

        // 2. Lock should be released (though file remains)
        let _lock2 = VaultLock::acquire(&lock_path).unwrap();
    }

    #[test]
    fn test_force_acquire() {
        let tmp = tempdir().unwrap();
        let lock_path = tmp.path().join("vault.lock");

        // Create a stale lock file (simulated by just existing)
        std::fs::write(&lock_path, "stale").unwrap();

        // Force acquire should work
        let _lock = VaultLock::force_acquire(&lock_path).unwrap();
        assert!(lock_path.exists());
    }
}
