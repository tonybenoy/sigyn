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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prod_policy() {
        let p = EnvironmentPolicy::default_for("prod");
        assert_eq!(p.env_name, "prod");
        assert!(p.require_approval);
        assert_eq!(p.min_approvals, 2);
        assert!(p.allowed_promoters.is_empty());
    }

    #[test]
    fn test_staging_policy() {
        let p = EnvironmentPolicy::default_for("staging");
        assert!(p.require_approval);
        assert_eq!(p.min_approvals, 0);
    }

    #[test]
    fn test_dev_policy() {
        let p = EnvironmentPolicy::default_for("dev");
        assert!(!p.require_approval);
        assert_eq!(p.min_approvals, 0);
    }

    #[test]
    fn test_custom_env_policy() {
        let p = EnvironmentPolicy::default_for("testing");
        assert!(!p.require_approval);
        assert_eq!(p.min_approvals, 0);
    }
}
