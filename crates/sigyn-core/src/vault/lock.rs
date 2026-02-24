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

        let mut lock = RwLock::new(file);
        let _ = lock.try_write().map_err(|_| {
            SigynError::LockFailed(format!(
                "vault is locked by another process ({}). If stale, delete the lock file or use force-unlock.",
                lock_path.display()
            ))
        })?;

        Ok(Self { _lock: lock })
    }

    pub fn force_acquire(lock_path: &Path) -> Result<Self> {
        if lock_path.exists() {
            std::fs::remove_file(lock_path)?;
        }
        Self::acquire(lock_path)
    }
}
