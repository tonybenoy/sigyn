use super::vector_clock::VectorClock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LwwEntry<V> {
    pub value: V,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub clock: VectorClock,
    pub writer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LwwMap<V> {
    pub entries: HashMap<String, LwwEntry<V>>,
}

impl<V: Clone> LwwMap<V> {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn set(&mut self, key: String, value: V, writer: String, clock: &VectorClock) {
        self.entries.insert(
            key,
            LwwEntry {
                value,
                timestamp: chrono::Utc::now(),
                clock: clock.clone(),
                writer,
            },
        );
    }

    pub fn get(&self, key: &str) -> Option<&V> {
        self.entries.get(key).map(|e| &e.value)
    }

    pub fn merge(&mut self, other: &LwwMap<V>) {
        for (key, other_entry) in &other.entries {
            match self.entries.get(key) {
                Some(local_entry) => {
                    if other_entry.timestamp > local_entry.timestamp {
                        self.entries.insert(key.clone(), other_entry.clone());
                    }
                }
                None => {
                    self.entries.insert(key.clone(), other_entry.clone());
                }
            }
        }
    }
}
