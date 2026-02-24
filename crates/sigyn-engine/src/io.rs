use std::path::Path;

use sigyn_core::error::{Result, SigynError};

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
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
