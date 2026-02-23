use serde::{Deserialize, Serialize};
use crate::crypto::keys::KeyFingerprint;
use crate::vault::PlaintextEnv;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PromotionStatus {
    Pending,
    Approved,
    Rejected,
    Applied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionRequest {
    pub id: uuid::Uuid,
    pub source_env: String,
    pub target_env: String,
    pub requested_by: KeyFingerprint,
    pub approvals: Vec<KeyFingerprint>,
    pub status: PromotionStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub keys_to_promote: Vec<String>,
}

/// Result of a promotion operation, tracking which keys were promoted,
/// which were skipped (not present in source), and which overwrote
/// existing values in the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionResult {
    pub promoted_keys: Vec<String>,
    pub skipped_keys: Vec<String>,
    pub overwritten_keys: Vec<String>,
}

/// Promote secrets from one environment to another.
/// This copies all secrets from source_env to target_env, overwriting target values.
///
/// If `filter` is `Some`, only the listed keys will be promoted. Keys present in the
/// filter but absent from the source are recorded in `skipped_keys`.
///
/// If `filter` is `None`, all keys in the source are promoted.
pub fn promote_env(
    source: &PlaintextEnv,
    target: &mut PlaintextEnv,
    fingerprint: &KeyFingerprint,
    filter: Option<&[String]>,
) -> PromotionResult {
    let mut promoted_keys = Vec::new();
    let mut skipped_keys = Vec::new();
    let mut overwritten_keys = Vec::new();

    let keys_to_promote: Vec<String> = match filter {
        Some(keys) => keys.to_vec(),
        None => source.keys().cloned().collect(),
    };

    for key in keys_to_promote {
        match source.get(&key) {
            Some(entry) => {
                if target.get(&key).is_some() {
                    overwritten_keys.push(key.clone());
                }
                target.set(key.clone(), entry.value.clone(), fingerprint);
                promoted_keys.push(key);
            }
            None => {
                skipped_keys.push(key);
            }
        }
    }

    PromotionResult {
        promoted_keys,
        skipped_keys,
        overwritten_keys,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::types::SecretValue;

    fn make_fingerprint(byte: u8) -> KeyFingerprint {
        KeyFingerprint([byte; 16])
    }

    fn make_source_env() -> PlaintextEnv {
        let fp = make_fingerprint(1);
        let mut env = PlaintextEnv::new();
        env.set("DB_URL".into(), SecretValue::String("postgres://src".into()), &fp);
        env.set("API_KEY".into(), SecretValue::String("sk-source-123".into()), &fp);
        env.set("CACHE_URL".into(), SecretValue::String("redis://src".into()), &fp);
        env
    }

    #[test]
    fn test_full_promotion() {
        let source = make_source_env();
        let fp = make_fingerprint(2);
        let mut target = PlaintextEnv::new();
        target.set("OLD_KEY".into(), SecretValue::String("old".into()), &fp);

        let result = promote_env(&source, &mut target, &fp, None);

        assert_eq!(result.promoted_keys.len(), 3);
        assert!(result.skipped_keys.is_empty());
        assert!(result.overwritten_keys.is_empty());

        // Verify all source keys are in target
        assert_eq!(
            target.get("DB_URL").unwrap().value,
            SecretValue::String("postgres://src".into())
        );
        assert_eq!(
            target.get("API_KEY").unwrap().value,
            SecretValue::String("sk-source-123".into())
        );
        assert_eq!(
            target.get("CACHE_URL").unwrap().value,
            SecretValue::String("redis://src".into())
        );
        // Old key should still be there (promotion only adds/overwrites)
        assert!(target.get("OLD_KEY").is_some());
    }

    #[test]
    fn test_filtered_promotion() {
        let source = make_source_env();
        let fp = make_fingerprint(2);
        let mut target = PlaintextEnv::new();
        target.set("DB_URL".into(), SecretValue::String("postgres://target".into()), &fp);

        let filter = vec!["DB_URL".to_string(), "API_KEY".to_string(), "NONEXISTENT".to_string()];
        let result = promote_env(&source, &mut target, &fp, Some(&filter));

        assert_eq!(result.promoted_keys, vec!["DB_URL", "API_KEY"]);
        assert_eq!(result.skipped_keys, vec!["NONEXISTENT"]);
        assert_eq!(result.overwritten_keys, vec!["DB_URL"]);

        // DB_URL should have been overwritten with source value
        assert_eq!(
            target.get("DB_URL").unwrap().value,
            SecretValue::String("postgres://src".into())
        );
        // CACHE_URL should NOT be in target (not in filter)
        assert!(target.get("CACHE_URL").is_none());
    }

    #[test]
    fn test_empty_source_promotion() {
        let source = PlaintextEnv::new();
        let fp = make_fingerprint(2);
        let mut target = PlaintextEnv::new();
        target.set("EXISTING".into(), SecretValue::String("val".into()), &fp);

        let result = promote_env(&source, &mut target, &fp, None);

        assert!(result.promoted_keys.is_empty());
        assert!(result.skipped_keys.is_empty());
        assert!(result.overwritten_keys.is_empty());
        // Target should be unchanged
        assert!(target.get("EXISTING").is_some());
    }
}
