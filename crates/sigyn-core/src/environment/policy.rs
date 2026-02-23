use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentPolicy {
    pub env_name: String,
    pub require_approval: bool,
    pub min_approvals: u32,
    pub allowed_promoters: Vec<crate::crypto::keys::KeyFingerprint>,
}

impl EnvironmentPolicy {
    pub fn default_for(env_name: &str) -> Self {
        let require_approval = env_name == "prod" || env_name == "staging";
        Self {
            env_name: env_name.to_string(),
            require_approval,
            min_approvals: if env_name == "prod" { 2 } else { 0 },
            allowed_promoters: Vec::new(),
        }
    }
}
