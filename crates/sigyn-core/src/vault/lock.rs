use std::fs::{File, OpenOptions};
use std::path::Path;

use fd_lock::RwLock;

use crate::error::{SigynError, Result};

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
        let _ = lock.try_write()
            .map_err(|e| SigynError::LockFailed(e.to_string()))?;

        Ok(Self { _lock: lock })
    }
}
