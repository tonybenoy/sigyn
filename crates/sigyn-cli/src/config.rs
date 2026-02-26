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

pub fn load_config() -> CliConfig {
    let config_path = sigyn_home().join("config.toml");
    if config_path.exists() {
        let content = std::fs::read_to_string(&config_path).unwrap_or_default();
        toml::from_str(&content).unwrap_or_default()
    } else {
        CliConfig::default()
    }
}

pub fn save_config(config: &CliConfig) -> anyhow::Result<()> {
    let home = sigyn_home();
    std::fs::create_dir_all(&home)?;
    let content = toml::to_string_pretty(config)?;
    std::fs::write(home.join("config.toml"), content)?;
    Ok(())
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
