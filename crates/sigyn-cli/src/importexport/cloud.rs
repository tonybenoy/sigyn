use anyhow::{Context, Result};
use std::process::Command;

/// Run an external CLI command and return its stdout as a string.
fn run_cli_command(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .context(format!("{} not found. Is it installed and on PATH?", cmd))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{} failed: {}", cmd, stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Parse a JSON string as a flat key-value object.
/// If the string is valid JSON object, returns key-value pairs.
/// Otherwise returns None.
pub fn parse_json_kv(json_str: &str) -> Option<Vec<(String, String)>> {
    let parsed: serde_json::Value = serde_json::from_str(json_str).ok()?;
    let obj = parsed.as_object()?;

    let pairs: Vec<(String, String)> = obj
        .iter()
        .map(|(k, v)| {
            let val = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            (k.clone(), val)
        })
        .collect();

    Some(pairs)
}

/// Import secrets from Doppler via CLI (`doppler secrets download --format json`).
///
/// Shells out to the `doppler` CLI, parses the resulting JSON, and filters
/// out Doppler metadata keys (those starting with `DOPPLER_`).
pub fn import_doppler(project: &str, config: &str) -> Result<Vec<(String, String)>> {
    let output = run_cli_command(
        "doppler",
        &[
            "secrets",
            "download",
            "--project",
            project,
            "--config",
            config,
            "--format",
            "json",
            "--no-file",
        ],
    )?;

    let pairs = parse_doppler_json(&output)?;
    Ok(pairs)
}

/// Parse Doppler JSON output, filtering out DOPPLER_ metadata keys.
pub fn parse_doppler_json(json_str: &str) -> Result<Vec<(String, String)>> {
    let parsed: serde_json::Value =
        serde_json::from_str(json_str).context("failed to parse Doppler JSON output")?;

    let obj = parsed
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Doppler output is not a JSON object"))?;

    let pairs: Vec<(String, String)> = obj
        .iter()
        .filter(|(k, _)| !k.starts_with("DOPPLER_"))
        .map(|(k, v)| {
            let val = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            (k.clone(), val)
        })
        .collect();

    Ok(pairs)
}

/// Import a secret from AWS Secrets Manager via CLI.
///
/// Retrieves the secret value using the `aws` CLI, extracts the `SecretString`
/// field, and attempts to parse it as JSON key-value pairs. If the secret is
/// not JSON, it is returned as a single entry keyed by `secret_id`.
pub fn import_aws_secret(
    secret_id: &str,
    region: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let mut args = vec![
        "secretsmanager",
        "get-secret-value",
        "--secret-id",
        secret_id,
        "--output",
        "json",
    ];

    if let Some(r) = region {
        args.push("--region");
        args.push(r);
    }

    let output = run_cli_command("aws", &args)?;
    let pairs = parse_aws_json(&output, secret_id)?;
    Ok(pairs)
}

/// Parse AWS Secrets Manager JSON response, extracting the SecretString.
pub fn parse_aws_json(json_str: &str, secret_id: &str) -> Result<Vec<(String, String)>> {
    let parsed: serde_json::Value =
        serde_json::from_str(json_str).context("failed to parse AWS CLI JSON output")?;

    let secret_string = parsed
        .get("SecretString")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "AWS response missing 'SecretString' field. \
                 Binary secrets (SecretBinary) are not supported."
            )
        })?;

    // Try to parse SecretString as JSON key-value pairs
    match parse_json_kv(secret_string) {
        Some(pairs) if !pairs.is_empty() => Ok(pairs),
        _ => {
            // Not JSON or empty — return as single key-value
            Ok(vec![(secret_id.to_string(), secret_string.to_string())])
        }
    }
}

/// Import a secret from GCP Secret Manager via CLI.
///
/// Accesses a specific version (or `latest`) of the named secret using the
/// `gcloud` CLI. Attempts to parse the result as JSON; falls back to a single
/// key-value pair if not JSON.
pub fn import_gcp_secret(
    project: &str,
    secret_name: &str,
    version: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let ver = version.unwrap_or("latest");
    let secret_arg = format!("--secret={}", secret_name);
    let project_arg = format!("--project={}", project);

    let output = run_cli_command(
        "gcloud",
        &[
            "secrets",
            "versions",
            "access",
            ver,
            &secret_arg,
            &project_arg,
        ],
    )?;

    let pairs = parse_gcp_output(&output, secret_name);
    Ok(pairs)
}

/// Parse GCP secret output: try JSON, fall back to single key-value.
pub fn parse_gcp_output(output: &str, secret_name: &str) -> Vec<(String, String)> {
    match parse_json_kv(output) {
        Some(pairs) if !pairs.is_empty() => pairs,
        _ => vec![(secret_name.to_string(), output.trim().to_string())],
    }
}

/// Import secrets from 1Password via CLI.
///
/// Retrieves an item from the specified vault using the `op` CLI and extracts
/// fields that have a value (filtering for `CONCEALED` type fields and any
/// field with a non-empty value).
pub fn import_1password(vault: &str, item: &str) -> Result<Vec<(String, String)>> {
    let output = run_cli_command(
        "op",
        &["item", "get", item, "--vault", vault, "--format", "json"],
    )?;

    let pairs = parse_1password_json(&output)?;
    Ok(pairs)
}

/// Parse 1Password CLI JSON output, extracting fields with values.
pub fn parse_1password_json(json_str: &str) -> Result<Vec<(String, String)>> {
    let parsed: serde_json::Value =
        serde_json::from_str(json_str).context("failed to parse 1Password CLI JSON output")?;

    let fields = parsed
        .get("fields")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("1Password response missing 'fields' array"))?;

    let mut pairs = Vec::new();

    for field in fields {
        let field_type = field.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let value = field.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let label = field.get("label").and_then(|v| v.as_str()).unwrap_or("");

        // Skip fields without a label or value
        if label.is_empty() || value.is_empty() {
            continue;
        }

        // Include CONCEALED fields (passwords/secrets) and any field with a value
        if field_type == "CONCEALED" || !value.is_empty() {
            pairs.push((label.to_string(), value.to_string()));
        }
    }

    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_json_kv ----

    #[test]
    fn test_parse_json_kv_valid_object() {
        let json = r#"{"DB_URL": "postgres://localhost", "PORT": "5432"}"#;
        let pairs = parse_json_kv(json).unwrap();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("DB_URL".to_string(), "postgres://localhost".to_string())));
        assert!(pairs.contains(&("PORT".to_string(), "5432".to_string())));
    }

    #[test]
    fn test_parse_json_kv_non_string_values() {
        let json = r#"{"COUNT": 42, "ENABLED": true}"#;
        let pairs = parse_json_kv(json).unwrap();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("COUNT".to_string(), "42".to_string())));
        assert!(pairs.contains(&("ENABLED".to_string(), "true".to_string())));
    }

    #[test]
    fn test_parse_json_kv_not_object() {
        assert!(parse_json_kv("[1, 2, 3]").is_none());
        assert!(parse_json_kv("\"hello\"").is_none());
        assert!(parse_json_kv("42").is_none());
    }

    #[test]
    fn test_parse_json_kv_invalid_json() {
        assert!(parse_json_kv("not json at all").is_none());
    }

    #[test]
    fn test_parse_json_kv_empty_object() {
        let pairs = parse_json_kv("{}").unwrap();
        assert!(pairs.is_empty());
    }

    // ---- Doppler ----

    #[test]
    fn test_parse_doppler_json_filters_metadata() {
        let json = r#"{
            "DB_URL": "postgres://localhost",
            "API_KEY": "sk-test-123",
            "DOPPLER_PROJECT": "my-project",
            "DOPPLER_CONFIG": "dev",
            "DOPPLER_ENVIRONMENT": "development"
        }"#;

        let pairs = parse_doppler_json(json).unwrap();
        assert_eq!(pairs.len(), 2);

        let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"DB_URL"));
        assert!(keys.contains(&"API_KEY"));
        assert!(!keys.iter().any(|k| k.starts_with("DOPPLER_")));
    }

    #[test]
    fn test_parse_doppler_json_empty() {
        let pairs = parse_doppler_json("{}").unwrap();
        assert!(pairs.is_empty());
    }

    #[test]
    fn test_parse_doppler_json_all_metadata() {
        let json = r#"{"DOPPLER_PROJECT": "p", "DOPPLER_CONFIG": "c"}"#;
        let pairs = parse_doppler_json(json).unwrap();
        assert!(pairs.is_empty());
    }

    #[test]
    fn test_parse_doppler_json_invalid() {
        assert!(parse_doppler_json("not json").is_err());
    }

    #[test]
    fn test_parse_doppler_json_not_object() {
        assert!(parse_doppler_json("[1,2,3]").is_err());
    }

    // ---- AWS Secrets Manager ----

    #[test]
    fn test_parse_aws_json_kv_secret() {
        let json = r#"{
            "ARN": "arn:aws:secretsmanager:us-east-1:123456:secret:myapp/prod-abc123",
            "Name": "myapp/prod",
            "SecretString": "{\"DB_HOST\": \"prod-db.example.com\", \"DB_PASS\": \"hunter2\"}",
            "VersionId": "abc-123"
        }"#;

        let pairs = parse_aws_json(json, "myapp/prod").unwrap();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("DB_HOST".to_string(), "prod-db.example.com".to_string())));
        assert!(pairs.contains(&("DB_PASS".to_string(), "hunter2".to_string())));
    }

    #[test]
    fn test_parse_aws_json_plain_string_secret() {
        let json = r#"{
            "ARN": "arn:aws:secretsmanager:us-east-1:123456:secret:api-key-abc123",
            "Name": "api-key",
            "SecretString": "sk-live-abcdef123456",
            "VersionId": "abc-123"
        }"#;

        let pairs = parse_aws_json(json, "api-key").unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("api-key".to_string(), "sk-live-abcdef123456".to_string()));
    }

    #[test]
    fn test_parse_aws_json_missing_secret_string() {
        let json = r#"{"ARN": "arn:...", "Name": "test"}"#;
        assert!(parse_aws_json(json, "test").is_err());
    }

    #[test]
    fn test_parse_aws_json_invalid() {
        assert!(parse_aws_json("not json", "test").is_err());
    }

    // ---- GCP Secret Manager ----

    #[test]
    fn test_parse_gcp_output_json() {
        let output = r#"{"DB_URL": "postgres://prod", "API_KEY": "key123"}"#;
        let pairs = parse_gcp_output(output, "my-secret");
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("DB_URL".to_string(), "postgres://prod".to_string())));
    }

    #[test]
    fn test_parse_gcp_output_plain_string() {
        let output = "my-plain-secret-value\n";
        let pairs = parse_gcp_output(output, "my-secret");
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            pairs[0],
            ("my-secret".to_string(), "my-plain-secret-value".to_string())
        );
    }

    #[test]
    fn test_parse_gcp_output_empty() {
        let pairs = parse_gcp_output("", "my-secret");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("my-secret".to_string(), "".to_string()));
    }

    // ---- 1Password ----

    #[test]
    fn test_parse_1password_json() {
        let json = r#"{
            "id": "abc123",
            "title": "My Server",
            "fields": [
                {
                    "id": "username",
                    "type": "STRING",
                    "label": "username",
                    "value": "admin"
                },
                {
                    "id": "password",
                    "type": "CONCEALED",
                    "label": "password",
                    "value": "super-secret-pass"
                },
                {
                    "id": "notes",
                    "type": "STRING",
                    "label": "notesPlain",
                    "value": ""
                },
                {
                    "id": "api_key",
                    "type": "CONCEALED",
                    "label": "API Key",
                    "value": "sk-test-999"
                },
                {
                    "id": "empty_label",
                    "type": "STRING",
                    "label": "",
                    "value": "should-be-skipped"
                }
            ]
        }"#;

        let pairs = parse_1password_json(json).unwrap();
        assert_eq!(pairs.len(), 3);
        assert!(pairs.contains(&("username".to_string(), "admin".to_string())));
        assert!(pairs.contains(&("password".to_string(), "super-secret-pass".to_string())));
        assert!(pairs.contains(&("API Key".to_string(), "sk-test-999".to_string())));
    }

    #[test]
    fn test_parse_1password_json_no_fields() {
        let json = r#"{"id": "abc", "title": "Test"}"#;
        assert!(parse_1password_json(json).is_err());
    }

    #[test]
    fn test_parse_1password_json_empty_fields() {
        let json = r#"{"fields": []}"#;
        let pairs = parse_1password_json(json).unwrap();
        assert!(pairs.is_empty());
    }

    #[test]
    fn test_parse_1password_json_invalid() {
        assert!(parse_1password_json("not json").is_err());
    }
}
