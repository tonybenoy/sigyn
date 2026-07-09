use super::promotion::{PromotionRequest, PromotionStatus};
use crate::crypto::keys::KeyFingerprint;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Per-environment promotion policy.
///
/// This governs how many approvals a promotion INTO `env_name` requires and,
/// optionally, which members are allowed to approve it. The approval rules are
/// enforced by [`EnvironmentPolicy::authorize_promotion`] /
/// [`EnvironmentPolicy::check_approvals`], which the `env promote` command
/// invokes at promote time for the target environment (see
/// [`EnvironmentPolicy::configured_for`]).
///
/// NOTE: the CLI does not yet persist a signed per-environment policy or run an
/// approval-collection workflow, so [`configured_for`](Self::configured_for)
/// currently returns `None` and the approval gate is inert *by configuration*
/// (not by being ignored). The RBAC access checks in `env promote` — Read on
/// the source env and Write on the target env — are the active promotion
/// controls today. See the module docs for what a full approval workflow needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentPolicy {
    pub env_name: String,
    pub require_approval: bool,
    pub min_approvals: u32,
    pub allowed_promoters: Vec<KeyFingerprint>,
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

    /// Number of distinct approvals that must be present before a promotion
    /// INTO this environment may proceed.
    ///
    /// `require_approval` and `min_approvals` are reconciled here: a policy that
    /// requires approval always needs at least one approver, even if
    /// `min_approvals` was left at its default of 0.
    pub fn effective_min_approvals(&self) -> u32 {
        if self.require_approval {
            self.min_approvals.max(1)
        } else {
            self.min_approvals
        }
    }

    /// Whether promotions into this environment are gated on approvals at all.
    pub fn requires_approval(&self) -> bool {
        self.effective_min_approvals() > 0
    }

    /// Enforce this environment's promotion-approval policy against a set of
    /// collected approvals.
    ///
    /// Rules:
    /// * If the policy does not require approval, any promotion is allowed.
    /// * The requester may never approve their own promotion, so `requester` is
    ///   not counted even if it appears in `approvals`.
    /// * When `allowed_promoters` is non-empty, only approvals from listed
    ///   fingerprints count; approvals from anyone else are ignored.
    /// * Duplicate approvals from the same fingerprint count once.
    /// * At least [`effective_min_approvals`](Self::effective_min_approvals)
    ///   distinct valid approvals must be present.
    ///
    /// Returns `Err(reason)` describing why the promotion is not yet authorized.
    pub fn check_approvals(
        &self,
        approvals: &[KeyFingerprint],
        requester: &KeyFingerprint,
    ) -> Result<(), String> {
        let required = self.effective_min_approvals();
        if required == 0 {
            return Ok(());
        }

        let allowed: Option<BTreeSet<&KeyFingerprint>> = if self.allowed_promoters.is_empty() {
            None
        } else {
            Some(self.allowed_promoters.iter().collect())
        };

        let mut counted: BTreeSet<&KeyFingerprint> = BTreeSet::new();
        for fp in approvals {
            if fp == requester {
                continue; // no self-approval
            }
            if let Some(ref allowed) = allowed {
                if !allowed.contains(fp) {
                    continue; // not an authorized promoter for this env
                }
            }
            counted.insert(fp);
        }

        let have = counted.len() as u32;
        if have < required {
            return Err(format!(
                "environment '{}' requires {} approval(s) to promote into, \
                 but only {} valid approval(s) were provided",
                self.env_name, required, have
            ));
        }
        Ok(())
    }

    /// Enforce this environment's promotion-approval policy against a
    /// [`PromotionRequest`].
    ///
    /// This is the richer entry point used by an approval-collection workflow:
    /// it verifies the request actually targets this environment and has not
    /// been rejected, then delegates to
    /// [`check_approvals`](Self::check_approvals).
    pub fn authorize_promotion(&self, request: &PromotionRequest) -> Result<(), String> {
        if request.target_env != self.env_name {
            return Err(format!(
                "promotion request targets env '{}' but this policy governs env '{}'",
                request.target_env, self.env_name
            ));
        }
        if matches!(request.status, PromotionStatus::Rejected) {
            return Err("promotion request has been rejected".to_string());
        }
        self.check_approvals(&request.approvals, &request.requested_by)
    }

    /// Load the promotion-approval policy configured for `env_name`, if any.
    ///
    /// Approval-gated promotion is enforced at promote time **only when a policy
    /// is configured for the target environment**. There is currently no
    /// persisted, signed per-environment policy store (nor an approval-
    /// collection workflow) in the CLI, so this returns `None` today. It is the
    /// single integration point where a future signed policy source should be
    /// wired in.
    ///
    /// It deliberately does NOT fall back to
    /// [`default_for`](Self::default_for): doing so would hard-block promotion
    /// into name-matched environments (e.g. "prod") with no mechanism to supply
    /// the required approvals, breaking a workflow instead of securing it.
    pub fn configured_for(_env_name: &str) -> Option<Self> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(byte: u8) -> KeyFingerprint {
        KeyFingerprint([byte; 16])
    }

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

    #[test]
    fn test_effective_min_approvals_reconciles_require_approval() {
        // require_approval with min_approvals 0 still needs 1 approver.
        let staging = EnvironmentPolicy::default_for("staging");
        assert_eq!(staging.effective_min_approvals(), 1);
        assert!(staging.requires_approval());

        // prod keeps its explicit count.
        let prod = EnvironmentPolicy::default_for("prod");
        assert_eq!(prod.effective_min_approvals(), 2);

        // dev requires nothing.
        let dev = EnvironmentPolicy::default_for("dev");
        assert_eq!(dev.effective_min_approvals(), 0);
        assert!(!dev.requires_approval());
    }

    #[test]
    fn test_check_approvals_no_gating_when_not_required() {
        let dev = EnvironmentPolicy::default_for("dev");
        // No approvals, no requester relevance: allowed.
        assert!(dev.check_approvals(&[], &fp(1)).is_ok());
    }

    #[test]
    fn test_check_approvals_requires_enough_distinct_approvers() {
        let prod = EnvironmentPolicy::default_for("prod"); // needs 2
        let requester = fp(1);

        // Zero approvals -> denied.
        assert!(prod.check_approvals(&[], &requester).is_err());

        // One approval -> still denied.
        assert!(prod.check_approvals(&[fp(2)], &requester).is_err());

        // Two distinct approvals -> allowed.
        assert!(prod.check_approvals(&[fp(2), fp(3)], &requester).is_ok());
    }

    #[test]
    fn test_check_approvals_ignores_self_and_duplicates() {
        let prod = EnvironmentPolicy::default_for("prod"); // needs 2
        let requester = fp(1);

        // Self-approval doesn't count, and duplicates collapse to one.
        assert!(prod
            .check_approvals(&[requester.clone(), fp(2), fp(2)], &requester)
            .is_err());

        // Requester + two genuinely distinct others.
        assert!(prod
            .check_approvals(&[requester.clone(), fp(2), fp(3)], &requester)
            .is_ok());
    }

    #[test]
    fn test_check_approvals_honors_allowed_promoters() {
        let mut prod = EnvironmentPolicy::default_for("prod"); // needs 2
        prod.allowed_promoters = vec![fp(10), fp(11), fp(12)];
        let requester = fp(1);

        // Approvals from non-listed members are ignored.
        assert!(prod.check_approvals(&[fp(2), fp(3)], &requester).is_err());

        // Mixed: only listed approvers count -> one valid -> denied.
        assert!(prod.check_approvals(&[fp(10), fp(3)], &requester).is_err());

        // Two listed approvers -> allowed.
        assert!(prod.check_approvals(&[fp(10), fp(11)], &requester).is_ok());
    }

    #[test]
    fn test_authorize_promotion_target_mismatch() {
        let prod = EnvironmentPolicy::default_for("prod");
        let request = PromotionRequest {
            id: uuid::Uuid::new_v4(),
            source_env: "staging".into(),
            target_env: "staging".into(), // does not match `prod`
            requested_by: fp(1),
            approvals: vec![fp(2), fp(3)],
            status: PromotionStatus::Pending,
            created_at: chrono::Utc::now(),
            keys_to_promote: vec![],
        };
        assert!(prod.authorize_promotion(&request).is_err());
    }

    #[test]
    fn test_authorize_promotion_rejected_status() {
        let prod = EnvironmentPolicy::default_for("prod");
        let request = PromotionRequest {
            id: uuid::Uuid::new_v4(),
            source_env: "staging".into(),
            target_env: "prod".into(),
            requested_by: fp(1),
            approvals: vec![fp(2), fp(3)],
            status: PromotionStatus::Rejected,
            created_at: chrono::Utc::now(),
            keys_to_promote: vec![],
        };
        assert!(prod.authorize_promotion(&request).is_err());
    }

    #[test]
    fn test_authorize_promotion_allows_when_satisfied() {
        let prod = EnvironmentPolicy::default_for("prod");
        let request = PromotionRequest {
            id: uuid::Uuid::new_v4(),
            source_env: "staging".into(),
            target_env: "prod".into(),
            requested_by: fp(1),
            approvals: vec![fp(2), fp(3)],
            status: PromotionStatus::Pending,
            created_at: chrono::Utc::now(),
            keys_to_promote: vec![],
        };
        assert!(prod.authorize_promotion(&request).is_ok());
    }

    #[test]
    fn test_configured_for_returns_none_until_wired() {
        // No persisted per-env policy store exists yet.
        assert!(EnvironmentPolicy::configured_for("prod").is_none());
        assert!(EnvironmentPolicy::configured_for("dev").is_none());
    }
}
