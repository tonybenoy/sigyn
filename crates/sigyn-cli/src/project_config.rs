use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ProjectConfig {
    pub project: Option<ProjectSettings>,
    #[serde(default)]
    pub commands: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectSettings {
    pub vault: Option<String>,
    pub env: Option<String>,
    pub identity: Option<String>,
}

/// Walk up from `start_dir` to find `.sigyn.toml`, returning the parsed config
/// and the directory it was found in.
pub fn find_project_config(start_dir: &Path) -> Option<(ProjectConfig, PathBuf)> {
    let mut dir = start_dir.to_path_buf();
    loop {
        let candidate = dir.join(".sigyn.toml");
        if candidate.is_file() {
            let content = std::fs::read_to_string(&candidate).ok()?;
            let config: ProjectConfig = toml::from_str(&content).ok()?;
            return Some((config, dir));
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Load project config from CWD or parent directories,
/// falling back to `~/.sigyn/project.toml`.
pub fn load_project_config() -> Option<ProjectConfig> {
    let cwd = std::env::current_dir().ok()?;
    if let Some((cfg, _)) = find_project_config(&cwd) {
        return Some(cfg);
    }

    // Fallback: ~/.sigyn/project.toml
    let global = crate::config::sigyn_home().join("project.toml");
    if global.is_file() {
        let content = std::fs::read_to_string(&global).ok()?;
        let config: ProjectConfig = toml::from_str(&content).ok()?;
        return Some(config);
    }

    None
}
