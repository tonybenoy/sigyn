use std::path::{Path, PathBuf};

use sigyn_core::error::{Result, SigynError};

/// Resolve a target path ensuring it stays within the expected parent directory.
///
/// Returns an error if the resolved path escapes the parent (e.g. via symlink).
pub fn safe_resolve(base: &Path, target: &Path) -> Result<PathBuf> {
    let canonical_base = base.canonicalize().unwrap_or_else(|_| base.to_path_buf());
    let canonical_target = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());
    if !canonical_target.starts_with(&canonical_base) {
        return Err(SigynError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "path escapes base directory: {} is not under {}",
                canonical_target.display(),
                canonical_base.display()
            ),
        )));
    }
    Ok(canonical_target)
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;

    // After creating dirs, verify the target path does not escape the parent
    // directory via symlink traversal.
    if path.exists() {
        let canonical_dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if !canonical_path.starts_with(&canonical_dir) {
            return Err(SigynError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "target path escapes parent directory: {} is not under {}",
                    canonical_path.display(),
                    canonical_dir.display()
                ),
            )));
        }
    }

    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(data)?;
    let file = tmp.persist(path).map_err(|e| SigynError::Io(e.error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let _ = file;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_write_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        atomic_write(&path, b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn test_safe_resolve_normal_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "data").unwrap();
        assert!(safe_resolve(dir.path(), &file).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_safe_resolve_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&outside_file, "secret").unwrap();

        let link = dir.path().join("escape");
        std::os::unix::fs::symlink(&outside_file, &link).unwrap();

        assert!(safe_resolve(dir.path(), &link).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_atomic_write_rejects_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("target.txt");
        std::fs::write(&outside_file, "original").unwrap();

        // Create a symlink inside dir pointing to outside
        let link = dir.path().join("escape.txt");
        std::os::unix::fs::symlink(&outside_file, &link).unwrap();

        let result = atomic_write(&link, b"overwritten");
        assert!(result.is_err());
        // Original file should not be modified
        assert_eq!(std::fs::read_to_string(&outside_file).unwrap(), "original");
    }
}
