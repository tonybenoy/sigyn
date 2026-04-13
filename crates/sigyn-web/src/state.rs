use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::session::SessionStore;

/// Shared application state passed to all handlers via axum's State extractor.
#[derive(Clone)]
pub struct AppState {
    pub sessions: Arc<SessionStore>,
    pub sigyn_home: PathBuf,
    pub session_timeout: Duration,
}

impl AppState {
    pub fn new(sigyn_home: PathBuf, session_timeout: Duration) -> Self {
        Self {
            sessions: Arc::new(SessionStore::new(session_timeout)),
            sigyn_home,
            session_timeout,
        }
    }
}
