use std::path::{Path, PathBuf};

use sigyn_core::error::{Result, SigynError};

/// Resolve a target path ensuring it stays within the expected parent directory.
///
/// Returns an error if the resolved path escapes the parent (e.g. via symlink),
/// or if the base directory cannot be canonicalized (must exist).
pub fn safe_resolve(base: &Path, target: &Path) -> Result<PathBuf> {
    let canonical_base = base.canonicalize().map_err(|e| {
        SigynError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "base directory does not exist or is inaccessible: {}",
                base.display()
            ),
        ))
    })?;
    // For the target, canonicalize if it exists; otherwise canonicalize its
    // parent and append the file name to catch symlinked parent directories.
    let canonical_target = if target.exists() {
        target.canonicalize().map_err(SigynError::Io)?
    } else if let Some(parent) = target.parent() {
        if parent.exists() {
            let canonical_parent = parent.canonicalize().map_err(SigynError::Io)?;
            match target.file_name() {
                Some(name) => canonical_parent.join(name),
                None => canonical_parent,
            }
        } else {
            // Neither target nor its parent exist — use the path as-is
            // (will be created under the base by create_dir_all)
            target.to_path_buf()
        }
    } else {
        target.to_path_buf()
    };
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

/// Walk up the path components and reject if any existing component is a symlink.
fn reject_symlinks_in_path(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if current.exists()
            && current
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        {
            return Err(SigynError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("path contains symlink: {}", current.display()),
            )));
        }
    }
    Ok(())
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;

    // Reject symlinks anywhere in the path to prevent symlink traversal attacks.
    // Check each component of the path for symlinks.
    reject_symlinks_in_path(path)?;

    // Also check if the target itself is a symlink (for existing files)
    if path.exists() {
        let canonical_dir = dir.canonicalize().map_err(SigynError::Io)?;
        let canonical_path = path.canonicalize().map_err(SigynError::Io)?;
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

    #[cfg(unix)]
    #[test]
    fn test_atomic_write_rejects_symlinked_parent_for_new_file() {
        let base = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        // Create a symlink inside base that points to outside dir
        let link_dir = base.path().join("escape-dir");
        std::os::unix::fs::symlink(outside.path(), &link_dir).unwrap();

        // Try to write a new file through the symlinked parent
        let target = link_dir.join("new-file.txt");
        let result = atomic_write(&target, b"data");
        assert!(
            result.is_err(),
            "should reject write through symlinked parent directory"
        );
        assert!(!outside.path().join("new-file.txt").exists());
    }

    #[test]
    fn test_safe_resolve_rejects_nonexistent_base() {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("does-not-exist");
        let target = nonexistent.join("file.txt");
        assert!(safe_resolve(&nonexistent, &target).is_err());
    }
}
