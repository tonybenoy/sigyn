use crate::crypto::keys::KeyFingerprint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

    /// Standard vector-clock partial order: self < other iff every component of
    /// self is <= the corresponding component of other, with at least one
    /// strictly less. A key absent from either clock counts as 0, so an
    /// explicitly stored 0 behaves identically to a missing entry.
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
        for (key, &value) in &other.clocks {
            if value > 0 && !self.clocks.contains_key(key) {
                at_least_one_less = true;
            }
        }
        at_least_one_less
    }

    /// Component-wise equality under the same convention as `happened_before`:
    /// missing keys count as 0, so `{}` equals `{a: 0}`.
    fn components_equal(&self, other: &VectorClock) -> bool {
        self.clocks
            .iter()
            .all(|(k, &v)| v == other.clocks.get(k).copied().unwrap_or(0))
            && other
                .clocks
                .iter()
                .all(|(k, &v)| v == self.clocks.get(k).copied().unwrap_or(0))
    }

    pub fn concurrent_with(&self, other: &VectorClock) -> bool {
        !self.happened_before(other)
            && !other.happened_before(self)
            && !self.components_equal(other)
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

    /// Build a clock directly from (node, count) pairs, keeping explicit zeros.
    fn clock(entries: &[(&str, u64)]) -> VectorClock {
        VectorClock {
            clocks: entries.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }

    /// Strip explicit-zero entries, producing the canonical form of a clock.
    fn normalized(vc: &VectorClock) -> VectorClock {
        VectorClock {
            clocks: vc
                .clocks
                .iter()
                .filter(|(_, &v)| v > 0)
                .map(|(k, &v)| (k.clone(), v))
                .collect(),
        }
    }

    #[test]
    fn test_explicit_zero_equals_absent_key() {
        // {} and {a: 0} are the same clock: neither happened before the other,
        // and they are not concurrent.
        let empty = clock(&[]);
        let zero = clock(&[("a", 0)]);

        assert!(!empty.happened_before(&zero));
        assert!(!zero.happened_before(&empty));
        assert!(!empty.concurrent_with(&zero));
        assert!(!zero.concurrent_with(&empty));
    }

    #[test]
    fn test_explicit_zero_extra_entry_equality() {
        // {a: 1, b: 0} and {a: 1} are the same clock.
        let with_zero = clock(&[("a", 1), ("b", 0)]);
        let without = clock(&[("a", 1)]);

        assert!(!with_zero.happened_before(&without));
        assert!(!without.happened_before(&with_zero));
        assert!(!with_zero.concurrent_with(&without));
    }

    #[test]
    fn test_explicit_zero_ordering_still_detected() {
        // {a: 0} < {a: 1}, exactly like {} < {a: 1}.
        let zero = clock(&[("a", 0)]);
        let one = clock(&[("a", 1)]);
        assert!(zero.happened_before(&one));
        assert!(!one.happened_before(&zero));

        // Zero-clock happened before any clock with a positive entry elsewhere.
        let other = clock(&[("b", 1)]);
        assert!(zero.happened_before(&other));
        assert!(!other.happened_before(&zero));
    }

    #[test]
    fn test_zero_entries_behave_like_normalized_clocks() {
        // Property: for every pair, comparisons on clocks containing explicit
        // zeros must agree with comparisons on their normalized (zero-free)
        // forms.
        let samples = [
            clock(&[]),
            clock(&[("a", 0)]),
            clock(&[("a", 1)]),
            clock(&[("a", 1), ("b", 0)]),
            clock(&[("a", 0), ("b", 2)]),
            clock(&[("a", 2), ("b", 1)]),
            clock(&[("a", 1), ("b", 2), ("c", 0)]),
            clock(&[("b", 2)]),
            clock(&[("c", 0), ("d", 0)]),
        ];

        for x in &samples {
            for y in &samples {
                let (nx, ny) = (normalized(x), normalized(y));
                assert_eq!(
                    x.happened_before(y),
                    nx.happened_before(&ny),
                    "happened_before mismatch for {:?} vs {:?}",
                    x,
                    y
                );
                assert_eq!(
                    x.concurrent_with(y),
                    nx.concurrent_with(&ny),
                    "concurrent_with mismatch for {:?} vs {:?}",
                    x,
                    y
                );
            }
        }
    }

    #[test]
    fn test_clock_never_happened_before_itself() {
        let vc = clock(&[("a", 1), ("b", 0)]);
        assert!(!vc.happened_before(&vc));
        assert!(!vc.concurrent_with(&vc));
    }
}
