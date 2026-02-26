use std::path::Path;

/// Result of project type detection.
pub struct ProjectDetection {
    /// Suggested vault name derived from the project manifest or directory.
    pub suggested_vault_name: String,
    /// Where the name was found (e.g. "package.json", "Cargo.toml", "directory name").
    pub source: &'static str,
}

/// Detect the project type from the current directory and suggest a vault name.
///
/// Checks (in order): `package.json`, `Cargo.toml`, `pyproject.toml`, `go.mod`,
/// then falls back to the current directory basename.
pub fn detect_project() -> ProjectDetection {
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(_) => {
            return ProjectDetection {
                suggested_vault_name: "default".into(),
                source: "fallback",
            };
        }
    };

    // 1. package.json
    if let Some(name) = read_package_json_name(&cwd) {
        return ProjectDetection {
            suggested_vault_name: sanitize(&name),
            source: "package.json",
        };
    }

    // 2. Cargo.toml
    if let Some(name) = read_cargo_toml_name(&cwd) {
        return ProjectDetection {
            suggested_vault_name: sanitize(&name),
            source: "Cargo.toml",
        };
    }

    // 3. pyproject.toml
    if let Some(name) = read_pyproject_name(&cwd) {
        return ProjectDetection {
            suggested_vault_name: sanitize(&name),
            source: "pyproject.toml",
        };
    }

    // 4. go.mod
    if let Some(name) = read_go_mod_name(&cwd) {
        return ProjectDetection {
            suggested_vault_name: sanitize(&name),
            source: "go.mod",
        };
    }

    // 5. Fall back to directory name
    let dir_name = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("default");

    ProjectDetection {
        suggested_vault_name: sanitize(dir_name),
        source: "directory name",
    }
}

/// Sanitize a project name into a valid vault name.
///
/// Lowercases, replaces non-alphanumeric (except hyphens) with hyphens,
/// collapses consecutive hyphens, trims leading/trailing hyphens, and
/// truncates to 64 characters.
fn sanitize(name: &str) -> String {
    let s: String = name
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();

    // Collapse consecutive hyphens
    let mut result = String::with_capacity(s.len());
    let mut prev_hyphen = false;
    for c in s.chars() {
        if c == '-' {
            if !prev_hyphen {
                result.push(c);
            }
            prev_hyphen = true;
        } else {
            result.push(c);
            prev_hyphen = false;
        }
    }

    // Trim leading/trailing hyphens and truncate
    let trimmed = result.trim_matches('-');
    if trimmed.is_empty() {
        "default".into()
    } else if trimmed.len() > 64 {
        trimmed[..64].trim_end_matches('-').to_string()
    } else {
        trimmed.to_string()
    }
}

fn read_package_json_name(dir: &Path) -> Option<String> {
    let content = std::fs::read_to_string(dir.join("package.json")).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    let name = parsed.get("name")?.as_str()?;
    if name.is_empty() {
        return None;
    }
    // Strip npm scope (e.g. "@scope/name" -> "name")
    let clean = if let Some(stripped) = name.strip_prefix('@') {
        stripped.split('/').nth(1).unwrap_or(stripped)
    } else {
        name
    };
    Some(clean.to_string())
}

fn read_cargo_toml_name(dir: &Path) -> Option<String> {
    let content = std::fs::read_to_string(dir.join("Cargo.toml")).ok()?;
    let parsed: toml::Value = toml::from_str(&content).ok()?;
    let name = parsed.get("package")?.get("name")?.as_str()?;
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

fn read_pyproject_name(dir: &Path) -> Option<String> {
    let content = std::fs::read_to_string(dir.join("pyproject.toml")).ok()?;
    let parsed: toml::Value = toml::from_str(&content).ok()?;
    let name = parsed.get("project")?.get("name")?.as_str()?;
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

fn read_go_mod_name(dir: &Path) -> Option<String> {
    let content = std::fs::read_to_string(dir.join("go.mod")).ok()?;
    let first_line = content.lines().next()?;
    let module_path = first_line.strip_prefix("module")?.trim();
    // Take the last path segment
    let name = module_path.rsplit('/').next().unwrap_or(module_path);
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_basic() {
        assert_eq!(sanitize("My App"), "my-app");
        assert_eq!(sanitize("my_cool_project"), "my-cool-project");
        assert_eq!(sanitize("@scope/package-name"), "scope-package-name");
        assert_eq!(sanitize("---leading---"), "leading");
        assert_eq!(sanitize(""), "default");
    }

    #[test]
    fn test_sanitize_truncation() {
        let long_name = "a".repeat(100);
        let result = sanitize(&long_name);
        assert!(result.len() <= 64);
    }

    #[test]
    fn test_read_package_json_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name": "@myorg/cool-app", "version": "1.0.0"}"#,
        )
        .unwrap();
        assert_eq!(read_package_json_name(dir.path()), Some("cool-app".into()));
    }

    #[test]
    fn test_read_cargo_toml_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"my-crate\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        assert_eq!(read_cargo_toml_name(dir.path()), Some("my-crate".into()));
    }

    #[test]
    fn test_read_pyproject_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"my-python-app\"\n",
        )
        .unwrap();
        assert_eq!(
            read_pyproject_name(dir.path()),
            Some("my-python-app".into())
        );
    }

    #[test]
    fn test_read_go_mod_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("go.mod"),
            "module github.com/user/my-service\n\ngo 1.21\n",
        )
        .unwrap();
        assert_eq!(read_go_mod_name(dir.path()), Some("my-service".into()));
    }
}
