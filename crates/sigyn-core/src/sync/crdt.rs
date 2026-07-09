//! Last-writer-wins (LWW) CRDT map with tombstones and vector-clock causality.
//!
//! Each key maps to an [`LwwEntry`] carrying a value (or a tombstone), a
//! wall-clock timestamp, a [`VectorClock`] capturing causal history, and the
//! writer's fingerprint. [`LwwMap::merge`] combines two replicas into a single
//! convergent state by applying the following rule to each key's local and
//! remote entry:
//!
//! 1. **Causality first.** If one entry's vector clock strictly
//!    [`happened_before`](VectorClock::happened_before) the other, the causally
//!    later entry wins, regardless of wall-clock time. This is what stops a stale
//!    concurrent write from resurrecting a newer delete (or a stale delete from
//!    burying a newer write).
//! 2. **Wall clock on conflict.** If the two clocks are concurrent (or equal),
//!    the entry with the later timestamp wins.
//! 3. **Deterministic tiebreak.** If the timestamps are also equal, the winner is
//!    chosen by comparing the writer fingerprint and then the value itself, so the
//!    result never depends on merge order.
//!
//! Deletions are represented as tombstones ([`LwwValue::Deleted`]) rather than by
//! dropping the key, so a delete carries a timestamp and clock and competes in the
//! ordering above on equal footing with an ordinary write; it therefore cannot be
//! silently undone by a concurrent-but-older write.
//!
//! Because every key's winner is selected as the maximum of the two entries under
//! a fixed total order ([`LwwEntry::merge_cmp`]), the merge is commutative
//! (`merge(a, b) == merge(b, a)`) and idempotent (`merge(a, a) == a`): replicas
//! that have observed the same set of writes converge to the same state.

use super::vector_clock::VectorClock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;

/// The state stored for a key: a live value or a tombstone recording a deletion.
///
/// Tombstones are retained (rather than removing the key) so that a delete carries
/// a timestamp and vector clock and can win or lose a merge just like an ordinary
/// write. The derived `Ord` provides the deterministic value tiebreak used as a
/// last resort in [`LwwEntry::merge_cmp`]; the variant order (`Present` before
/// `Deleted`) is arbitrary but fixed, which is all convergence requires.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LwwValue<V> {
    /// A live value written to the key.
    Present(V),
    /// A tombstone marking the key as deleted.
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LwwEntry<V> {
    pub value: LwwValue<V>,
    pub timestamp: DateTime<Utc>,
    pub clock: VectorClock,
    pub writer: String,
}

impl<V: Ord> LwwEntry<V> {
    /// Total order over entries used by [`LwwMap::merge`]: the greater entry wins.
    ///
    /// The ordering is decided in three stages, matching the module-level rule:
    /// causal dominance (a causally later entry is always greater), then
    /// wall-clock timestamp, then a deterministic tiebreak on the writer
    /// fingerprint and finally the value. Because this is antisymmetric and total,
    /// taking the maximum of two entries is both commutative and idempotent, which
    /// is what makes the merge convergent.
    fn merge_cmp(&self, other: &Self) -> Ordering {
        // 1. Causality wins outright: a causally later entry dominates regardless
        //    of the wall clock (which may be skewed or non-monotonic).
        if self.clock.happened_before(&other.clock) {
            return Ordering::Less;
        }
        if other.clock.happened_before(&self.clock) {
            return Ordering::Greater;
        }
        // 2. Concurrent (or causally equal) entries: the later timestamp wins.
        match self.timestamp.cmp(&other.timestamp) {
            Ordering::Equal => {}
            ord => return ord,
        }
        // 3. Equal timestamps: break the tie deterministically so the outcome is
        //    independent of the order in which replicas merge.
        match self.writer.cmp(&other.writer) {
            Ordering::Equal => {}
            ord => return ord,
        }
        self.value.cmp(&other.value)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct LwwMap<V> {
    pub entries: HashMap<String, LwwEntry<V>>,
}

impl<V: Clone> LwwMap<V> {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Write `value` to `key`, stamped with the current wall-clock time.
    pub fn set(&mut self, key: String, value: V, writer: String, clock: &VectorClock) {
        self.set_at(key, value, writer, clock, Utc::now());
    }

    /// Write `value` to `key` with an explicit timestamp.
    ///
    /// Exposing the timestamp lets callers (and tests) supply a logical or
    /// externally-sourced time instead of the process wall clock.
    pub fn set_at(
        &mut self,
        key: String,
        value: V,
        writer: String,
        clock: &VectorClock,
        timestamp: DateTime<Utc>,
    ) {
        self.entries.insert(
            key,
            LwwEntry {
                value: LwwValue::Present(value),
                timestamp,
                clock: clock.clone(),
                writer,
            },
        );
    }

    /// Delete `key` by writing a tombstone, stamped with the current wall-clock
    /// time. The tombstone participates in merges like any other write, so the
    /// deletion is not resurrected by a concurrent-but-older value.
    pub fn remove(&mut self, key: String, writer: String, clock: &VectorClock) {
        self.remove_at(key, writer, clock, Utc::now());
    }

    /// Delete `key` by writing a tombstone with an explicit timestamp.
    pub fn remove_at(
        &mut self,
        key: String,
        writer: String,
        clock: &VectorClock,
        timestamp: DateTime<Utc>,
    ) {
        self.entries.insert(
            key,
            LwwEntry {
                value: LwwValue::Deleted,
                timestamp,
                clock: clock.clone(),
                writer,
            },
        );
    }

    /// Return the live value for `key`, or `None` if it is absent or tombstoned.
    pub fn get(&self, key: &str) -> Option<&V> {
        self.entries.get(key).and_then(|entry| match &entry.value {
            LwwValue::Present(value) => Some(value),
            LwwValue::Deleted => None,
        })
    }

    /// Merge `other` into `self`, keeping the winning entry for every key.
    ///
    /// For keys present in both maps the winner is the maximum under
    /// [`LwwEntry::merge_cmp`]; keys present in only one map are carried over
    /// unchanged. The operation is commutative and idempotent (see the module
    /// docs).
    pub fn merge(&mut self, other: &LwwMap<V>)
    where
        V: Ord,
    {
        for (key, other_entry) in &other.entries {
            let other_wins = match self.entries.get(key) {
                Some(local_entry) => other_entry.merge_cmp(local_entry) == Ordering::Greater,
                None => true,
            };
            if other_wins {
                self.entries.insert(key.clone(), other_entry.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a vector clock directly from `(node, count)` pairs.
    fn clock(entries: &[(&str, u64)]) -> VectorClock {
        VectorClock {
            clocks: entries.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }

    /// Deterministic timestamp `secs` seconds after the Unix epoch.
    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    fn merged(a: &LwwMap<String>, b: &LwwMap<String>) -> LwwMap<String> {
        let mut out = a.clone();
        out.merge(b);
        out
    }

    /// A pair of maps exercising every branch of the merge rule: causal
    /// dominance, concurrent conflict resolved by timestamp, an exact tie resolved
    /// by writer, tombstones, and single-sided keys.
    fn sample_pair() -> (LwwMap<String>, LwwMap<String>) {
        let mut a = LwwMap::new();
        let mut b = LwwMap::new();

        // Causal: b's clock dominates a's, even though a has the later timestamp.
        a.set_at(
            "causal".into(),
            "old".into(),
            "n1".into(),
            &clock(&[("n1", 1)]),
            ts(100),
        );
        b.set_at(
            "causal".into(),
            "new".into(),
            "n1".into(),
            &clock(&[("n1", 2)]),
            ts(5),
        );

        // Concurrent clocks: later timestamp wins.
        a.set_at(
            "concurrent".into(),
            "A".into(),
            "n1".into(),
            &clock(&[("n1", 1)]),
            ts(5),
        );
        b.set_at(
            "concurrent".into(),
            "B".into(),
            "n2".into(),
            &clock(&[("n2", 1)]),
            ts(9),
        );

        // Exact tie (concurrent, equal timestamp): writer fingerprint decides.
        a.set_at(
            "tie".into(),
            "x".into(),
            "aaa".into(),
            &clock(&[("n1", 1)]),
            ts(7),
        );
        b.set_at(
            "tie".into(),
            "y".into(),
            "bbb".into(),
            &clock(&[("n2", 1)]),
            ts(7),
        );

        // Causal delete: b's tombstone causally follows a's write.
        a.set_at(
            "del".into(),
            "live".into(),
            "n1".into(),
            &clock(&[("n1", 1)]),
            ts(100),
        );
        b.remove_at("del".into(), "n1".into(), &clock(&[("n1", 2)]), ts(1));

        // Single-sided keys.
        a.set_at(
            "only_a".into(),
            "a".into(),
            "n1".into(),
            &clock(&[("n1", 1)]),
            ts(1),
        );
        b.set_at(
            "only_b".into(),
            "b".into(),
            "n2".into(),
            &clock(&[("n2", 1)]),
            ts(1),
        );

        (a, b)
    }

    #[test]
    fn set_and_get() {
        let mut map = LwwMap::new();
        map.set(
            "key1".into(),
            "val1".to_string(),
            "node1".into(),
            &clock(&[]),
        );
        assert_eq!(map.get("key1"), Some(&"val1".to_string()));
        assert_eq!(map.get("missing"), None);
    }

    #[test]
    fn remove_hides_value() {
        let mut map = LwwMap::new();
        map.set_at(
            "k".into(),
            "v".into(),
            "n1".into(),
            &clock(&[("n1", 1)]),
            ts(1),
        );
        assert_eq!(map.get("k"), Some(&"v".to_string()));
        map.remove_at("k".into(), "n1".into(), &clock(&[("n1", 2)]), ts(2));
        assert_eq!(map.get("k"), None);
    }

    #[test]
    fn merge_is_commutative() {
        let (a, b) = sample_pair();
        // Whole-map equality (HashMap PartialEq is order-independent).
        assert_eq!(merged(&a, &b), merged(&b, &a));
    }

    #[test]
    fn merge_is_idempotent() {
        let (a, _) = sample_pair();
        assert_eq!(merged(&a, &a), a);
        // A second merge with the peer must not change an already-merged replica.
        let (a, b) = sample_pair();
        let once = merged(&a, &b);
        let twice = merged(&once, &b);
        assert_eq!(once, twice);
    }

    #[test]
    fn merge_resolves_expected_winners() {
        let (a, b) = sample_pair();
        let m = merged(&a, &b);
        assert_eq!(m.get("causal"), Some(&"new".to_string())); // causal dominance
        assert_eq!(m.get("concurrent"), Some(&"B".to_string())); // later timestamp
        assert_eq!(m.get("tie"), Some(&"y".to_string())); // writer "bbb" > "aaa"
        assert_eq!(m.get("del"), None); // causal tombstone
        assert_eq!(m.get("only_a"), Some(&"a".to_string()));
        assert_eq!(m.get("only_b"), Some(&"b".to_string()));
    }

    #[test]
    fn concurrent_older_write_does_not_resurrect_tombstone() {
        // A delete and a concurrent write with an OLDER timestamp: the delete has
        // the later wall clock, so the tombstone must survive.
        let mut deleted = LwwMap::<String>::new();
        deleted.remove_at("k".into(), "n1".into(), &clock(&[("n1", 2)]), ts(50));

        let mut writer = LwwMap::<String>::new();
        writer.set_at(
            "k".into(),
            "resurrect".into(),
            "n2".into(),
            &clock(&[("n2", 1)]),
            ts(20),
        );

        assert_eq!(merged(&deleted, &writer).get("k"), None);
        assert_eq!(merged(&writer, &deleted).get("k"), None);
    }

    #[test]
    fn causal_delete_beats_newer_timestamped_write() {
        // The classic resurrection bug: a write with a NEWER timestamp that is
        // nonetheless causally BEFORE the delete must not win. Timestamp-only LWW
        // would resurrect the value here.
        let mut written = LwwMap::<String>::new();
        written.set_at(
            "k".into(),
            "stale".into(),
            "n1".into(),
            &clock(&[("n1", 1)]),
            ts(999),
        );

        let mut deleted = LwwMap::<String>::new();
        deleted.remove_at("k".into(), "n1".into(), &clock(&[("n1", 2)]), ts(1));

        assert_eq!(merged(&written, &deleted).get("k"), None);
        assert_eq!(merged(&deleted, &written).get("k"), None);
    }

    #[test]
    fn causal_write_beats_newer_timestamped_delete() {
        // Symmetric case: a write that causally follows a delete wins, even though
        // the delete carries a newer wall-clock timestamp.
        let mut deleted = LwwMap::<String>::new();
        deleted.remove_at("k".into(), "n1".into(), &clock(&[("n1", 2)]), ts(999));

        let mut written = LwwMap::<String>::new();
        written.set_at(
            "k".into(),
            "revived".into(),
            "n1".into(),
            &clock(&[("n1", 3)]),
            ts(1),
        );

        assert_eq!(
            merged(&deleted, &written).get("k"),
            Some(&"revived".to_string())
        );
        assert_eq!(
            merged(&written, &deleted).get("k"),
            Some(&"revived".to_string())
        );
    }

    #[test]
    fn concurrent_tiebreak_is_deterministic_by_writer() {
        // Concurrent clocks, identical timestamps, distinct writers: the higher
        // writer fingerprint always wins, in either merge order.
        let mut a = LwwMap::<String>::new();
        a.set_at(
            "k".into(),
            "from_a".into(),
            "aaa".into(),
            &clock(&[("n1", 1)]),
            ts(7),
        );
        let mut b = LwwMap::<String>::new();
        b.set_at(
            "k".into(),
            "from_b".into(),
            "bbb".into(),
            &clock(&[("n2", 1)]),
            ts(7),
        );

        assert_eq!(merged(&a, &b).get("k"), Some(&"from_b".to_string()));
        assert_eq!(merged(&b, &a).get("k"), Some(&"from_b".to_string()));
    }

    #[test]
    fn concurrent_tiebreak_is_deterministic_by_value() {
        // Concurrent clocks, identical timestamps AND identical writers: fall
        // through to the value comparison. "zebra" > "apple", so it wins in both
        // orders.
        let mut a = LwwMap::<String>::new();
        a.set_at(
            "k".into(),
            "apple".into(),
            "same".into(),
            &clock(&[("n1", 1)]),
            ts(7),
        );
        let mut b = LwwMap::<String>::new();
        b.set_at(
            "k".into(),
            "zebra".into(),
            "same".into(),
            &clock(&[("n2", 1)]),
            ts(7),
        );

        assert_eq!(merged(&a, &b).get("k"), Some(&"zebra".to_string()));
        assert_eq!(merged(&b, &a).get("k"), Some(&"zebra".to_string()));
    }

    #[test]
    fn equal_clocks_fall_back_to_timestamp() {
        // Two writes with identical (empty) clocks are neither ordered nor
        // strictly concurrent; the later timestamp must decide.
        let mut a = LwwMap::<String>::new();
        a.set_at("k".into(), "early".into(), "n1".into(), &clock(&[]), ts(1));
        let mut b = LwwMap::<String>::new();
        b.set_at("k".into(), "late".into(), "n2".into(), &clock(&[]), ts(2));

        assert_eq!(merged(&a, &b).get("k"), Some(&"late".to_string()));
        assert_eq!(merged(&b, &a).get("k"), Some(&"late".to_string()));
    }
}
