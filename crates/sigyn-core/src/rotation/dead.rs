use crate::vault::PlaintextEnv;

pub struct DeadSecretReport {
    pub key: String,
    pub env: String,
    pub last_accessed: Option<chrono::DateTime<chrono::Utc>>,
    pub age_days: i64,
}

pub fn find_dead_secrets(
    env: &PlaintextEnv,
    env_name: &str,
    max_age_days: i64,
) -> Vec<DeadSecretReport> {
    let cutoff = chrono::Utc::now() - chrono::Duration::days(max_age_days);
    let mut dead = Vec::new();

    for (key, entry) in &env.entries {
        if entry.metadata.updated_at < cutoff {
            let age = (chrono::Utc::now() - entry.metadata.updated_at).num_days();
            dead.push(DeadSecretReport {
                key: key.clone(),
                env: env_name.to_string(),
                last_accessed: Some(entry.metadata.updated_at),
                age_days: age,
            });
        }
    }

    dead
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyFingerprint;
    use crate::secrets::types::{SecretEntry, SecretMetadata, SecretValue};

    fn make_entry(key: &str, days_old: i64) -> (String, SecretEntry) {
        let fp = KeyFingerprint([0u8; 16]);
        let mut meta = SecretMetadata::new(fp);
        meta.updated_at = chrono::Utc::now() - chrono::Duration::days(days_old);
        (
            key.to_string(),
            SecretEntry {
                key: key.to_string(),
                value: SecretValue::String("val".to_string()),
                metadata: meta,
            },
        )
    }

    #[test]
    fn test_find_dead_secrets_old_entries() {
        let mut env = PlaintextEnv::new();
        let (k, e) = make_entry("OLD_KEY", 100);
        env.entries.insert(k, e);
        let (k, e) = make_entry("FRESH_KEY", 5);
        env.entries.insert(k, e);

        let dead = find_dead_secrets(&env, "dev", 30);
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].key, "OLD_KEY");
        assert_eq!(dead[0].env, "dev");
        assert!(dead[0].age_days >= 99);
    }

    #[test]
    fn test_find_dead_secrets_all_fresh() {
        let mut env = PlaintextEnv::new();
        let (k, e) = make_entry("A", 1);
        env.entries.insert(k, e);
        let (k, e) = make_entry("B", 2);
        env.entries.insert(k, e);

        let dead = find_dead_secrets(&env, "prod", 30);
        assert!(dead.is_empty());
    }

    #[test]
    fn test_find_dead_secrets_empty_env() {
        let env = PlaintextEnv::new();
        let dead = find_dead_secrets(&env, "dev", 30);
        assert!(dead.is_empty());
    }
}
