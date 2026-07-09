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
    // Delegates to a pure helper so tests can exercise the lookup rule without
    // mutating the process environment (which is a data race — and UB — against
    // every other thread reading the environment in a parallel test run).
    mfa_code_from(|k| std::env::var(k).ok())
}

/// The env-lookup rule for one-time MFA codes, parameterized over the getter so
/// it is testable in isolation: consult `SIGYN_MFA_CODE` only, never
/// `SIGYN_PASSPHRASE`.
fn mfa_code_from(getenv: impl Fn(&str) -> Option<String>) -> Option<String> {
    getenv("SIGYN_MFA_CODE")
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

    // Pure test of the env-lookup rule — no process-environment mutation, so it
    // cannot race with (or corrupt) other tests running in parallel.
    #[test]
    fn mfa_code_reads_only_sigyn_mfa_code_never_passphrase() {
        // Env where SIGYN_PASSPHRASE is set but SIGYN_MFA_CODE is not: the code
        // lookup must yield nothing — it must never fall back to the passphrase.
        let only_passphrase = |k: &str| match k {
            "SIGYN_PASSPHRASE" => Some("super-secret-passphrase".to_string()),
            _ => None,
        };
        assert_eq!(mfa_code_from(only_passphrase), None);

        // With SIGYN_MFA_CODE present, it returns exactly that code.
        let with_code = |k: &str| match k {
            "SIGYN_MFA_CODE" => Some("123456".to_string()),
            "SIGYN_PASSPHRASE" => Some("super-secret-passphrase".to_string()),
            _ => None,
        };
        assert_eq!(mfa_code_from(with_code), Some("123456".to_string()));
    }
}
