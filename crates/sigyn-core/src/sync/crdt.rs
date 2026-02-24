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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lww_map_basic() {
        let mut map = LwwMap::new();
        let clock = VectorClock::new();

        map.set("key1".into(), "val1".to_string(), "node1".into(), &clock);
        assert_eq!(map.get("key1"), Some(&"val1".to_string()));
        assert_eq!(map.get("key2"), None);
    }

    #[test]
    fn test_lww_map_merge() {
        let mut map1 = LwwMap::new();
        let mut map2 = LwwMap::new();
        let clock = VectorClock::new();

        map1.set("common".into(), "val1".into(), "node1".into(), &clock);
        map1.set("only1".into(), "val1".into(), "node1".into(), &clock);

        // Sleep briefly to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(10));

        map2.set("common".into(), "val2".into(), "node2".into(), &clock);
        map2.set("only2".into(), "val2".into(), "node2".into(), &clock);

        map1.merge(&map2);

        assert_eq!(map1.get("common"), Some(&"val2".to_string()));
        assert_eq!(map1.get("only1"), Some(&"val1".to_string()));
        assert_eq!(map1.get("only2"), Some(&"val2".to_string()));
    }
}
