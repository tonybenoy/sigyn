use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
    pub unchanged: Vec<String>,
}

impl EnvDiff {
    pub fn compute(
        source: &crate::vault::PlaintextEnv,
        target: &crate::vault::PlaintextEnv,
    ) -> Self {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut modified = Vec::new();
        let mut unchanged = Vec::new();

        for key in source.keys() {
            match target.get(key) {
                Some(target_entry) => {
                    let Some(source_entry) = source.get(key) else {
                        continue;
                    };
                    if source_entry.value == target_entry.value {
                        unchanged.push(key.clone());
                    } else {
                        modified.push(key.clone());
                    }
                }
                None => added.push(key.clone()),
            }
        }

        for key in target.keys() {
            if source.get(key).is_none() {
                removed.push(key.clone());
            }
        }

        Self {
            added,
            removed,
            modified,
            unchanged,
        }
    }

    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || !self.modified.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyFingerprint;
    use crate::secrets::types::SecretValue;
    use crate::vault::PlaintextEnv;

    fn make_env(pairs: &[(&str, &str)]) -> PlaintextEnv {
        let fp = KeyFingerprint([0u8; 16]);
        let mut env = PlaintextEnv::new();
        for (k, v) in pairs {
            env.set(k.to_string(), SecretValue::String(v.to_string()), &fp);
        }
        env
    }

    #[test]
    fn test_identical_envs() {
        let a = make_env(&[("A", "1"), ("B", "2")]);
        let b = make_env(&[("A", "1"), ("B", "2")]);
        let diff = EnvDiff::compute(&a, &b);
        assert!(!diff.has_changes());
        assert_eq!(diff.unchanged.len(), 2);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.modified.is_empty());
    }

    #[test]
    fn test_added_keys() {
        let source = make_env(&[("A", "1"), ("B", "2")]);
        let target = make_env(&[("A", "1")]);
        let diff = EnvDiff::compute(&source, &target);
        assert!(diff.has_changes());
        assert_eq!(diff.added, vec!["B"]);
        assert_eq!(diff.unchanged, vec!["A"]);
    }

    #[test]
    fn test_removed_keys() {
        let source = make_env(&[("A", "1")]);
        let target = make_env(&[("A", "1"), ("B", "2")]);
        let diff = EnvDiff::compute(&source, &target);
        assert!(diff.has_changes());
        assert_eq!(diff.removed, vec!["B"]);
    }

    #[test]
    fn test_modified_keys() {
        let source = make_env(&[("A", "old")]);
        let target = make_env(&[("A", "new")]);
        let diff = EnvDiff::compute(&source, &target);
        assert!(diff.has_changes());
        assert_eq!(diff.modified, vec!["A"]);
    }

    #[test]
    fn test_empty_envs() {
        let a = PlaintextEnv::new();
        let b = PlaintextEnv::new();
        let diff = EnvDiff::compute(&a, &b);
        assert!(!diff.has_changes());
    }

    #[test]
    fn test_mixed_changes() {
        let source = make_env(&[("KEEP", "same"), ("MOD", "v1"), ("ADD", "new")]);
        let target = make_env(&[("KEEP", "same"), ("MOD", "v2"), ("DEL", "old")]);
        let diff = EnvDiff::compute(&source, &target);
        assert!(diff.has_changes());
        assert!(diff.added.contains(&"ADD".to_string()));
        assert!(diff.removed.contains(&"DEL".to_string()));
        assert!(diff.modified.contains(&"MOD".to_string()));
        assert!(diff.unchanged.contains(&"KEEP".to_string()));
    }
}
