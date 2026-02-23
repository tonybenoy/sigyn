use anyhow::Result;
use sigyn_core::vault::PlaintextEnv;

#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    Dotenv,
    Json,
    ShellEval,
    DockerEnv,
    K8sSecret,
}

impl ExportFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "dotenv" | "env" => Ok(Self::Dotenv),
            "json" => Ok(Self::Json),
            "shell" | "shell-eval" => Ok(Self::ShellEval),
            "docker" | "docker-env" => Ok(Self::DockerEnv),
            "k8s" | "k8s-secret" | "kubernetes" => Ok(Self::K8sSecret),
            other => anyhow::bail!(
                "unknown format: '{}'. Use: dotenv, json, shell, docker, k8s",
                other
            ),
        }
    }
}

pub fn export_secrets(env: &PlaintextEnv, format: ExportFormat, name: &str) -> Result<String> {
    match format {
        ExportFormat::Dotenv => Ok(super::dotenv::format_dotenv(env)),
        ExportFormat::ShellEval => Ok(super::dotenv::format_shell_eval(env)),
        ExportFormat::DockerEnv => Ok(super::dotenv::format_docker_env(env)),
        ExportFormat::Json => {
            let map: serde_json::Map<String, serde_json::Value> = env
                .entries
                .iter()
                .filter_map(|(k, e)| {
                    e.value
                        .as_str()
                        .map(|v| (k.clone(), serde_json::Value::String(v.to_string())))
                })
                .collect();
            Ok(serde_json::to_string_pretty(&map)?)
        }
        ExportFormat::K8sSecret => {
            use base64::Engine;
            let mut data = serde_json::Map::new();
            for (key, entry) in &env.entries {
                if let Some(val) = entry.value.as_str() {
                    let encoded = base64::engine::general_purpose::STANDARD.encode(val);
                    data.insert(key.clone(), serde_json::Value::String(encoded));
                }
            }

            let secret = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": name,
                },
                "type": "Opaque",
                "data": data,
            });
            Ok(serde_json::to_string_pretty(&secret)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigyn_core::crypto::keys::KeyFingerprint;
    use sigyn_core::secrets::types::SecretValue;

    fn test_env() -> PlaintextEnv {
        let fp = KeyFingerprint([0u8; 16]);
        let mut env = PlaintextEnv::new();
        env.set(
            "DB_URL".into(),
            SecretValue::String("postgres://localhost".into()),
            &fp,
        );
        env.set(
            "API_KEY".into(),
            SecretValue::String("sk-test-123".into()),
            &fp,
        );
        env
    }

    #[test]
    fn test_export_dotenv() {
        let env = test_env();
        let out = export_secrets(&env, ExportFormat::Dotenv, "test").unwrap();
        assert!(out.contains("DB_URL=postgres://localhost"));
        assert!(out.contains("API_KEY=sk-test-123"));
    }

    #[test]
    fn test_export_json() {
        let env = test_env();
        let out = export_secrets(&env, ExportFormat::Json, "test").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["DB_URL"], "postgres://localhost");
    }

    #[test]
    fn test_export_k8s() {
        let env = test_env();
        let out = export_secrets(&env, ExportFormat::K8sSecret, "my-secrets").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["kind"], "Secret");
        assert_eq!(parsed["metadata"]["name"], "my-secrets");
    }
}
