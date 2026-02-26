use anyhow::Result;
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

/// Write a `.sigyn.toml` project config file to `path`.
pub fn write_project_config(
    path: &Path,
    vault: Option<&str>,
    identity: Option<&str>,
    env: &str,
) -> Result<()> {
    let mut lines = Vec::new();
    lines.push("[project]".to_string());
    if let Some(v) = vault {
        lines.push(format!("vault = \"{}\"", v));
    }
    lines.push(format!("env = \"{}\"", env));
    if let Some(i) = identity {
        lines.push(format!("identity = \"{}\"", i));
    }

    lines.push(String::new());
    lines.push("# Named commands — run with: sigyn run <name>".to_string());
    lines.push("[commands]".to_string());
    lines.push("# dev = \"npm run dev\"".to_string());
    lines.push("# app = \"./start-server\"".to_string());

    let content = lines.join("\n") + "\n";
    std::fs::write(path, &content)?;
    Ok(())
}

/// Offer to create `.sigyn.toml` if one does not exist and we are in an interactive terminal.
///
/// Returns `Ok(true)` if the config was created, `Ok(false)` if skipped.
pub fn offer_project_init(
    vault_name: &str,
    identity_name: Option<&str>,
    env_name: &str,
) -> Result<bool> {
    if !crate::config::is_interactive() {
        return Ok(false);
    }

    let cwd = std::env::current_dir()?;
    if find_project_config(&cwd).is_some() {
        return Ok(false);
    }

    let confirm = dialoguer::Confirm::new()
        .with_prompt("Create .sigyn.toml for this project?")
        .default(true)
        .interact()?;

    if !confirm {
        return Ok(false);
    }

    let target = cwd.join(".sigyn.toml");
    write_project_config(&target, Some(vault_name), identity_name, env_name)?;

    use console::style;
    crate::output::print_success(&format!("Created {}", target.display()));
    eprintln!(
        "  {}",
        style("Edit .sigyn.toml to add named commands and adjust settings.").dim()
    );

    Ok(true)
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
