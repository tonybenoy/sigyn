pub mod cloud;

use anyhow::Result;
use sigyn_core::crypto::keys::KeyFingerprint;
use sigyn_core::secrets::types::SecretValue;
use sigyn_core::vault::PlaintextEnv;

/// Import secrets from a .env file
pub fn import_dotenv(
    content: &str,
    env: &mut PlaintextEnv,
    fingerprint: &KeyFingerprint,
) -> Result<usize> {
    let mut count = 0;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = parse_dotenv_line(line) {
            env.set(key, SecretValue::String(value), fingerprint);
            count += 1;
        }
    }

    Ok(count)
}

fn parse_dotenv_line(line: &str) -> Option<(String, String)> {
    let line = line.strip_prefix("export ").unwrap_or(line);
    let eq_pos = line.find('=')?;
    let key = line[..eq_pos].trim().to_string();
    let mut value = line[eq_pos + 1..].trim().to_string();

    // Strip surrounding quotes
    if (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''))
    {
        value = value[1..value.len() - 1].to_string();
    }

    // Unescape
    value = value
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\\\", "\\")
        .replace("\\\"", "\"");

    if key.is_empty() {
        return None;
    }

    Some((key, value))
}

/// Import secrets from a JSON object (key: value pairs)
pub fn import_json(
    content: &str,
    env: &mut PlaintextEnv,
    fingerprint: &KeyFingerprint,
) -> Result<usize> {
    let parsed: serde_json::Value = serde_json::from_str(content)?;
    let obj = parsed
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("JSON must be an object with string key-value pairs"))?;

    let mut count = 0;
    for (key, value) in obj {
        let val_str = match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        env.set(key.clone(), SecretValue::String(val_str), fingerprint);
        count += 1;
    }

    Ok(count)
}

/// Import from a file, auto-detecting format
#[allow(dead_code)]
pub fn import_file(
    path: &std::path::Path,
    env: &mut PlaintextEnv,
    fingerprint: &KeyFingerprint,
) -> Result<usize> {
    let content = std::fs::read_to_string(path)?;

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "json" => import_json(&content, env, fingerprint),
        "env" | "dotenv" => import_dotenv(&content, env, fingerprint),
        _ => {
            // Try to auto-detect: if it starts with '{', treat as JSON
            if content.trim_start().starts_with('{') {
                import_json(&content, env, fingerprint)
            } else {
                import_dotenv(&content, env, fingerprint)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fp() -> KeyFingerprint {
        KeyFingerprint([0u8; 16])
    }

    #[test]
    fn test_import_dotenv_basic() {
        let content = r#"
# Database
DB_URL=postgres://localhost
API_KEY="sk-test-123"
SECRET='my secret'
export EXPORTED_VAR=hello
"#;
        let mut env = PlaintextEnv::new();
        let count = import_dotenv(content, &mut env, &test_fp()).unwrap();
        assert_eq!(count, 4);
        assert_eq!(
            env.get("DB_URL").unwrap().value.as_str(),
            Some("postgres://localhost")
        );
        assert_eq!(
            env.get("API_KEY").unwrap().value.as_str(),
            Some("sk-test-123")
        );
        assert_eq!(env.get("SECRET").unwrap().value.as_str(), Some("my secret"));
        assert_eq!(
            env.get("EXPORTED_VAR").unwrap().value.as_str(),
            Some("hello")
        );
    }

    #[test]
    fn test_import_json() {
        let content = r#"{"DB_URL": "postgres://localhost", "PORT": "5432"}"#;
        let mut env = PlaintextEnv::new();
        let count = import_json(content, &mut env, &test_fp()).unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            env.get("DB_URL").unwrap().value.as_str(),
            Some("postgres://localhost")
        );
    }

    #[test]
    fn test_import_dotenv_skip_comments_and_blanks() {
        let content = "# comment\n\nKEY=value\n  # another\n";
        let mut env = PlaintextEnv::new();
        let count = import_dotenv(content, &mut env, &test_fp()).unwrap();
        assert_eq!(count, 1);
    }
}
