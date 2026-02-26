use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct CliConfig {
    pub default_vault: Option<String>,
    pub default_env: Option<String>,
    pub default_identity: Option<String>,
    pub auto_sync: bool,
    pub json_output: bool,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            default_vault: None,
            default_env: Some("dev".into()),
            default_identity: None,
            auto_sync: false,
            json_output: false,
        }
    }
}

pub fn sigyn_home() -> PathBuf {
    if let Ok(home) = std::env::var("SIGYN_HOME") {
        return PathBuf::from(home);
    }
    directories::BaseDirs::new()
        .map(|d| d.home_dir().join(".sigyn"))
        .unwrap_or_else(|| PathBuf::from(".sigyn"))
}

/// Create the sigyn home directory with restrictive permissions (0o700).
/// This prevents other local users from reading config, manifests, or vault metadata.
pub fn ensure_sigyn_home() -> anyhow::Result<PathBuf> {
    let home = sigyn_home();
    std::fs::create_dir_all(&home)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(home)
}

/// Write a file with restrictive permissions (0o600 on Unix).
/// Uses atomic temp-file + rename on Unix to avoid a window where the file
/// is readable with default permissions.
pub fn secure_write(path: &std::path::Path, content: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    secure_write_unix(path, content)?;

    #[cfg(not(unix))]
    std::fs::write(path, content)?;

    Ok(())
}

#[cfg(unix)]
fn secure_write_unix(path: &std::path::Path, content: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let tmp_path = dir.join(format!(
        ".tmp.{}.{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)?;
    file.write_all(content)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

pub fn load_config() -> CliConfig {
    let home = sigyn_home();
    let config_path = home.join("config.toml");
    if !config_path.exists() {
        return CliConfig::default();
    }
    let data = match std::fs::read(&config_path) {
        Ok(d) => d,
        Err(_) => return CliConfig::default(),
    };
    if !sigyn_engine::crypto::sealed::is_sealed(&data) {
        eprintln!(
            "{} config.toml is not in sealed format — ignoring (possible tampering)",
            console::style("warning:").yellow().bold()
        );
        return CliConfig::default();
    }
    if let Ok(device_key) = sigyn_engine::device::load_or_create_device_key(&home) {
        if let Ok(cipher) =
            sigyn_engine::crypto::sealed::derive_file_cipher(&device_key, b"sigyn-config-v1")
        {
            if let Ok(plaintext) =
                sigyn_engine::crypto::sealed::sealed_decrypt(&cipher, &data, b"config.toml")
            {
                if let Ok(s) = std::str::from_utf8(&plaintext) {
                    return toml::from_str(s).unwrap_or_default();
                }
            }
        }
    }
    CliConfig::default()
}

fn save_config_inner(home: &std::path::Path, config: &CliConfig) -> anyhow::Result<()> {
    let content = toml::to_string_pretty(config)?;
    let device_key = sigyn_engine::device::load_or_create_device_key(home)?;
    let cipher = sigyn_engine::crypto::sealed::derive_file_cipher(&device_key, b"sigyn-config-v1")?;
    let sealed =
        sigyn_engine::crypto::sealed::sealed_encrypt(&cipher, content.as_bytes(), b"config.toml")?;
    secure_write(&home.join("config.toml"), &sealed)?;
    Ok(())
}

pub fn save_config(config: &CliConfig) -> anyhow::Result<()> {
    let home = ensure_sigyn_home()?;
    save_config_inner(&home, config)
}

/// Returns true if the terminal is interactive (safe to show prompts).
///
/// Returns false when stderr is not a terminal, or when running in CI
/// or with `SIGYN_NON_INTERACTIVE` set.
pub fn is_interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
        && std::env::var("CI").is_err()
        && std::env::var("SIGYN_NON_INTERACTIVE").is_err()
}
