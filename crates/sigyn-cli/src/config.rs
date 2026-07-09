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
/// Requires both stdin and stderr to be terminals: interactive prompts
/// (e.g. `dialoguer::Confirm`) read their answer from stdin, so a piped
/// stdin (`echo | sigyn run ...`) must be treated as non-interactive even
/// when stderr is a TTY — otherwise piped data silently answers the prompt.
/// Also returns false when running in CI or with `SIGYN_NON_INTERACTIVE` set.
pub fn is_interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
        && std::io::stderr().is_terminal()
        && std::env::var("CI").is_err()
        && std::env::var("SIGYN_NON_INTERACTIVE").is_err()
}

/// One-time MFA code supplied via the environment, if any.
///
/// Only `SIGYN_MFA_CODE` is consulted — never `SIGYN_PASSPHRASE`. A
/// passphrase is not a one-time code: falling back to it would silently
/// feed the passphrase into TOTP/backup-code prompts and make MFA
/// impossible to complete in any script or CI job that sets
/// `SIGYN_PASSPHRASE`.
fn mfa_code_from_env() -> Option<String> {
    std::env::var("SIGYN_MFA_CODE").ok()
}

/// Read a one-time MFA code (TOTP or backup code).
///
/// Unlike `read_passphrase`, this never falls back to `SIGYN_PASSPHRASE`.
/// For scripted/non-interactive use, supply the code via `SIGYN_MFA_CODE`.
pub fn read_code(prompt: &str) -> anyhow::Result<String> {
    if let Some(code) = mfa_code_from_env() {
        return Ok(code);
    }
    rpassword::prompt_password(prompt).map_err(|e| {
        anyhow::anyhow!(
            "failed to read MFA code (set SIGYN_MFA_CODE for non-interactive use): {}",
            e
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Single combined test so the env-var manipulation cannot race with a
    // parallel test case touching the same variables.
    #[test]
    fn test_read_code_never_returns_sigyn_passphrase() {
        std::env::set_var("SIGYN_PASSPHRASE", "super-secret-passphrase");

        // Without SIGYN_MFA_CODE, the env fast-path must yield nothing —
        // in particular it must never pick up SIGYN_PASSPHRASE. (The only
        // remaining path in read_code is an interactive TTY prompt.)
        std::env::remove_var("SIGYN_MFA_CODE");
        assert_eq!(mfa_code_from_env(), None);

        // With SIGYN_MFA_CODE set, read_code returns the code, not the
        // passphrase, and never touches the TTY.
        std::env::set_var("SIGYN_MFA_CODE", "123456");
        let code = read_code("unused prompt: ").unwrap();
        assert_eq!(code, "123456");
        assert_ne!(code, "super-secret-passphrase");

        std::env::remove_var("SIGYN_MFA_CODE");
        std::env::remove_var("SIGYN_PASSPHRASE");
    }
}
