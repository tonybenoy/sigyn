use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncStatus {
    UpToDate,
    LocalAhead(u64),
    RemoteAhead(u64),
    Diverged,
    NeverSynced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncState {
    pub status: SyncStatus,
    pub last_push: Option<chrono::DateTime<chrono::Utc>>,
    pub last_pull: Option<chrono::DateTime<chrono::Utc>>,
    pub remote_url: Option<String>,
}
