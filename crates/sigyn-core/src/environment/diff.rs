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
                    let source_entry = source.get(key).unwrap();
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
