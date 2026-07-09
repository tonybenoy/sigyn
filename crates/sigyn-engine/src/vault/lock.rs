use std::fs::{File, OpenOptions};
use std::path::Path;

use fd_lock::RwLock;

use crate::error::{Result, SigynError};

/// An exclusive advisory lock on a vault, held for the lifetime of this value.
///
/// The lock is an OS-level file lock (`flock` on Unix, `LockFileEx` on
/// Windows) on the lock file and is released when the `VaultLock` is dropped.
/// Because the OS owns the lock, it is also released automatically if the
/// process crashes — a leftover lock file on disk does NOT mean the vault is
/// locked.
///
/// # Same-process semantics
///
/// Acquisition is always non-blocking. Calling [`VaultLock::acquire`] while
/// another `VaultLock` on the same path is alive fails fast with
/// [`SigynError::LockFailed`] — **including from the same process**, because
/// each acquire opens a fresh file descriptor and OS file locks on separate
/// descriptors contend with each other. There is no deadlock hazard (nothing
/// blocks), but nested acquires will error: acquire the lock once per
/// command and pass it down.
pub struct VaultLock {
    /// The open, locked lock file. The OS lock is tied to this open file
    /// description; closing the file on drop releases the lock.
    _file: File,
}

impl VaultLock {
    /// Acquire an exclusive lock on `lock_path`, failing immediately with
    /// [`SigynError::LockFailed`] if it is already held (by any process,
    /// including this one). The lock is held until the returned `VaultLock`
    /// is dropped.
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
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    SigynError::LockFailed(format!("failed to set lock file permissions: {}", e))
                })?;
        }

        let mut lock = RwLock::new(file);
        let guard = lock.try_write().map_err(|_| {
            SigynError::LockFailed(format!(
                "vault is locked by another sigyn process or operation ({}). \
                 The lock is released automatically when that process exits.",
                lock_path.display()
            ))
        })?;

        // The guard borrows `lock`, so it cannot be stored in the struct
        // alongside it. Instead, deliberately skip the guard's Drop (which
        // would unlock immediately): the OS lock belongs to the open file
        // description and stays held until the file is closed when this
        // `VaultLock` is dropped.
        std::mem::forget(guard);
        Ok(Self {
            _file: lock.into_inner(),
        })
    }

    /// Force-acquire the lock by removing any stale lock file atomically.
    /// This avoids the TOCTOU of checking existence then removing — just
    /// attempt removal unconditionally (ENOENT is fine).
    ///
    /// Note: if another process still holds the lock, it keeps its lock on
    /// the now-unlinked inode; this call succeeds on a fresh file. Use only
    /// when the operator knows the holder is gone.
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
    fn test_second_acquire_contends_while_held() {
        let tmp = tempdir().unwrap();
        let lock_path = tmp.path().join("vault.lock");

        // Each acquire opens a fresh file descriptor, and OS file locks on
        // separate descriptors contend even within one process — so this
        // exercises the same kernel path as cross-process contention,
        // deterministically.
        let lock1 = VaultLock::acquire(&lock_path).unwrap();

        let second = VaultLock::acquire(&lock_path);
        assert!(
            matches!(second, Err(SigynError::LockFailed(_))),
            "second acquire must fail fast while the lock is held"
        );

        // Releasing the first lock allows re-acquisition.
        drop(lock1);
        let _lock3 = VaultLock::acquire(&lock_path)
            .expect("acquire must succeed after the previous lock is dropped");
    }

    #[test]
    fn test_contention_visible_from_other_thread() {
        let tmp = tempdir().unwrap();
        let lock_path = tmp.path().join("vault.lock");

        let _lock1 = VaultLock::acquire(&lock_path).unwrap();

        let path_clone = lock_path.clone();
        let handle = std::thread::spawn(move || VaultLock::acquire(&path_clone).is_err());
        assert!(
            handle.join().unwrap(),
            "acquire from another thread must fail while the lock is held"
        );
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
