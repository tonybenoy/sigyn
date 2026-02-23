use serde::{Deserialize, Serialize};
use crate::crypto::keys::KeyFingerprint;
use super::constraints::Constraints;
use super::roles::Role;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberPolicy {
    pub fingerprint: KeyFingerprint,
    pub role: Role,
    pub allowed_envs: Vec<String>,
    pub secret_patterns: Vec<String>,
    pub max_delegation_depth: u32,
    pub max_delegatees: u32,
    pub constraints: Option<Constraints>,
    pub delegated_by: Option<KeyFingerprint>,
    pub added_at: chrono::DateTime<chrono::Utc>,
}

impl MemberPolicy {
    pub fn new(fingerprint: KeyFingerprint, role: Role) -> Self {
        Self {
            fingerprint,
            role,
            allowed_envs: vec!["dev".into(), "staging".into(), "prod".into()],
            secret_patterns: vec!["*".into()],
            max_delegation_depth: 2,
            max_delegatees: 10,
            constraints: None,
            delegated_by: None,
            added_at: chrono::Utc::now(),
        }
    }
}
