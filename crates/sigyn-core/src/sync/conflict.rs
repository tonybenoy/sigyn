use super::vector_clock::VectorClock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    pub key: String,
    pub env: String,
    pub local_value: String,
    pub remote_value: String,
    pub local_clock: VectorClock,
    pub remote_clock: VectorClock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictResolution {
    TakeLocal,
    TakeRemote,
    TakeLatestTimestamp,
    TakeHigherRole,
    Merge(String),
    Defer,
}
