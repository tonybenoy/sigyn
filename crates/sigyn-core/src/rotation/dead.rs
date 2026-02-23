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
