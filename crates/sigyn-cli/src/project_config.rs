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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_find_project_config() {
        let root = tempdir().unwrap();
        let project_dir = root.path().join("myproject");
        let sub_dir = project_dir.join("src").join("utils");
        fs::create_dir_all(&sub_dir).unwrap();

        let config_content = r#"
[project]
vault = "myvault"
env = "dev"
"#;
        fs::write(project_dir.join(".sigyn.toml"), config_content).unwrap();

        // Should find it from sub-directory
        let (config, found_dir) = find_project_config(&sub_dir).expect("should find config");
        assert_eq!(found_dir, project_dir);
        assert_eq!(config.project.unwrap().vault, Some("myvault".into()));

        // Should find it from project directory
        let (config, found_dir) = find_project_config(&project_dir).expect("should find config");
        assert_eq!(found_dir, project_dir);
        assert_eq!(config.project.unwrap().env, Some("dev".into()));

        // Should NOT find it from root
        assert!(find_project_config(root.path()).is_none());
    }
}
