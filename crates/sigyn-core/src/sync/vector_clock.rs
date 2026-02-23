use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::crypto::keys::KeyFingerprint;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct VectorClock {
    pub clocks: HashMap<String, u64>,
}

impl VectorClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tick(&mut self, node_id: &KeyFingerprint) {
        let key = node_id.to_hex();
        let counter = self.clocks.entry(key).or_insert(0);
        *counter += 1;
    }

    pub fn merge(&mut self, other: &VectorClock) {
        for (key, &value) in &other.clocks {
            let entry = self.clocks.entry(key.clone()).or_insert(0);
            *entry = (*entry).max(value);
        }
    }

    pub fn happened_before(&self, other: &VectorClock) -> bool {
        let mut at_least_one_less = false;
        for (key, &value) in &self.clocks {
            let other_value = other.clocks.get(key).copied().unwrap_or(0);
            if value > other_value {
                return false;
            }
            if value < other_value {
                at_least_one_less = true;
            }
        }
        for key in other.clocks.keys() {
            if !self.clocks.contains_key(key) {
                at_least_one_less = true;
            }
        }
        at_least_one_less
    }

    pub fn concurrent_with(&self, other: &VectorClock) -> bool {
        !self.happened_before(other) && !other.happened_before(self) && self != other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_clock_ordering() {
        let fp1 = KeyFingerprint([1u8; 16]);
        let fp2 = KeyFingerprint([2u8; 16]);

        let mut vc1 = VectorClock::new();
        vc1.tick(&fp1);

        let mut vc2 = vc1.clone();
        vc2.tick(&fp2);

        assert!(vc1.happened_before(&vc2));
        assert!(!vc2.happened_before(&vc1));
    }

    #[test]
    fn test_concurrent_clocks() {
        let fp1 = KeyFingerprint([1u8; 16]);
        let fp2 = KeyFingerprint([2u8; 16]);

        let mut vc1 = VectorClock::new();
        vc1.tick(&fp1);

        let mut vc2 = VectorClock::new();
        vc2.tick(&fp2);

        assert!(vc1.concurrent_with(&vc2));
    }
}
