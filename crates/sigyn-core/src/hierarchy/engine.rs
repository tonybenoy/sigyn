use crate::crypto::keys::KeyFingerprint;
use crate::error::Result;
use crate::policy::acl::matches_secret_pattern;
use crate::policy::engine::{AccessRequest, PolicyDecision};
use crate::policy::member::MemberPolicy;
use crate::policy::storage::VaultPolicy;

/// A single level in the policy chain, from vault up to root org.
#[derive(Debug)]
pub struct PolicyLevel {
    pub owner: KeyFingerprint,
    pub policy: VaultPolicy,
}

/// Evaluates access requests against a chain of policies from vault → root org.
///
/// Rules:
/// 1. Owner at any level → Allow
/// 2. Collect all MemberPolicy entries for the actor across all levels
/// 3. Take highest role (max by Role::level())
/// 4. Union all allowed_envs (if any level grants "*", result is "*")
/// 5. Union all secret_patterns (if any level grants "*", result is "*")
/// 6. Build synthetic MemberPolicy, delegate to standard policy checks
pub struct HierarchicalPolicyEngine;

impl HierarchicalPolicyEngine {
    /// Evaluate an access request against a chain of policies.
    /// `chain` is ordered from vault (index 0) to root org (last index).
    pub fn evaluate(chain: &[PolicyLevel], request: &AccessRequest) -> Result<PolicyDecision> {
        // 1. Check if actor is owner at any level
        for level in chain {
            if request.actor == level.owner {
                return Ok(PolicyDecision::Allow);
            }
        }

        // 2. Collect all member policies for this actor across levels
        let mut member_entries: Vec<&MemberPolicy> = Vec::new();
        for level in chain {
            if let Some(member) = level.policy.get_member(&request.actor) {
                member_entries.push(member);
            }
        }

        if member_entries.is_empty() {
            return Ok(PolicyDecision::Deny("not a member at any level".into()));
        }

        // 3. Highest role wins
        let highest_role = member_entries
            .iter()
            .map(|m| m.role)
            .max_by_key(|r| r.level())
            .unwrap(); // safe: member_entries is non-empty

        // 4. Union allowed_envs
        let mut has_wildcard_env = false;
        let mut all_envs: Vec<String> = Vec::new();
        for m in &member_entries {
            for env in &m.allowed_envs {
                if env == "*" {
                    has_wildcard_env = true;
                } else if !all_envs.contains(env) {
                    all_envs.push(env.clone());
                }
            }
        }
        let merged_envs = if has_wildcard_env {
            vec!["*".into()]
        } else {
            all_envs
        };

        // 5. Union secret_patterns
        let mut has_wildcard_pattern = false;
        let mut all_patterns: Vec<String> = Vec::new();
        for m in &member_entries {
            for pat in &m.secret_patterns {
                if pat == "*" {
                    has_wildcard_pattern = true;
                } else if !all_patterns.contains(pat) {
                    all_patterns.push(pat.clone());
                }
            }
        }
        let merged_patterns = if has_wildcard_pattern {
            vec!["*".into()]
        } else {
            all_patterns
        };

        // 6. Check environment access
        if !merged_envs.iter().any(|e| e == "*" || e == &request.env) {
            return Ok(PolicyDecision::Deny(format!(
                "no access to env '{}'",
                request.env
            )));
        }

        // 7. Check action capability based on merged highest role
        use crate::policy::engine::AccessAction;
        match &request.action {
            AccessAction::Read => {
                if !highest_role.can_read() {
                    return Ok(PolicyDecision::Deny("role cannot read".into()));
                }
            }
            AccessAction::Write | AccessAction::Delete => {
                if !highest_role.can_write() {
                    return Ok(PolicyDecision::Deny("role cannot write".into()));
                }
            }
            AccessAction::ManageMembers => {
                if !highest_role.can_manage_members() {
                    return Ok(PolicyDecision::Deny("role cannot manage members".into()));
                }
            }
            AccessAction::ManagePolicy => {
                if !highest_role.can_manage_policy() {
                    return Ok(PolicyDecision::Deny("role cannot manage policy".into()));
                }
            }
            AccessAction::CreateEnv | AccessAction::Promote => {
                if !highest_role.can_manage_members() {
                    return Ok(PolicyDecision::Deny(
                        "role cannot manage environments".into(),
                    ));
                }
            }
            AccessAction::Audit => {
                if !highest_role.can_audit() {
                    return Ok(PolicyDecision::Deny("role cannot access audit logs".into()));
                }
            }
        }

        // 8. Check secret patterns
        if let Some(key) = &request.key {
            if !matches_secret_pattern(key, &merged_patterns)? {
                return Ok(PolicyDecision::Deny(format!("no access to key '{}'", key)));
            }
        }

        // 9. Check constraints from all levels — any constraint violation denies
        let now = chrono::Utc::now();
        for m in &member_entries {
            if let Some(constraints) = &m.constraints {
                if let Err(reason) = constraints.check(now) {
                    return Ok(PolicyDecision::Deny(reason));
                }
            }
        }

        // Check global constraints at all levels
        for level in chain {
            if let Some(global) = &level.policy.global_constraints {
                if let Err(reason) = global.check(now) {
                    return Ok(PolicyDecision::Deny(reason));
                }
            }
        }

        // 10. Check per-action MFA requirement from any level
        if !request.mfa_verified {
            for m in &member_entries {
                if m.constraints
                    .as_ref()
                    .is_some_and(|c| request.action.requires_mfa(&c.mfa_actions))
                {
                    return Ok(PolicyDecision::RequiresMfa);
                }
            }
            for level in chain {
                if level
                    .policy
                    .global_constraints
                    .as_ref()
                    .is_some_and(|c| request.action.requires_mfa(&c.mfa_actions))
                {
                    return Ok(PolicyDecision::RequiresMfa);
                }
            }
        }

        // 11. Check for expiring access (warning)
        let warn_threshold = chrono::Duration::hours(24);
        for m in &member_entries {
            if let Some(constraints) = &m.constraints {
                if let Some(expires_at) = constraints.expires_at {
                    let remaining = expires_at - now;
                    if remaining > chrono::Duration::zero() && remaining < warn_threshold {
                        return Ok(PolicyDecision::AllowWithWarning(format!(
                            "access expires in {} hours",
                            remaining.num_hours()
                        )));
                    }
                }
            }
        }

        Ok(PolicyDecision::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::engine::AccessAction;
    use crate::policy::roles::Role;

    fn fp(byte: u8) -> KeyFingerprint {
        KeyFingerprint([byte; 16])
    }

    fn make_request(actor: KeyFingerprint, action: AccessAction, env: &str) -> AccessRequest {
        AccessRequest {
            actor,
            action,
            env: env.into(),
            key: None,
            mfa_verified: false,
        }
    }

    #[test]
    fn test_single_level_owner_allowed() {
        let owner = fp(1);
        let chain = vec![PolicyLevel {
            owner: owner.clone(),
            policy: VaultPolicy::new(),
        }];
        let req = make_request(owner, AccessAction::ManagePolicy, "prod");
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn test_single_level_non_member_denied() {
        let owner = fp(1);
        let stranger = fp(2);
        let chain = vec![PolicyLevel {
            owner,
            policy: VaultPolicy::new(),
        }];
        let req = make_request(stranger, AccessAction::Read, "dev");
        assert!(matches!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn test_single_level_matches_existing_behavior() {
        let owner = fp(1);
        let member = fp(2);
        let mut policy = VaultPolicy::new();
        policy.add_member(MemberPolicy::new(member.clone(), Role::Contributor));

        let chain = vec![PolicyLevel { owner, policy }];

        // Can read
        let req = make_request(member.clone(), AccessAction::Read, "dev");
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );

        // Cannot manage members
        let req = make_request(member, AccessAction::ManageMembers, "dev");
        assert!(matches!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn test_multi_level_highest_role_wins() {
        let member = fp(2);

        // Vault level: ReadOnly
        let mut vault_policy = VaultPolicy::new();
        vault_policy.add_member(MemberPolicy::new(member.clone(), Role::ReadOnly));

        // Org level: Admin
        let mut org_policy = VaultPolicy::new();
        org_policy.add_member(MemberPolicy::new(member.clone(), Role::Admin));

        let chain = vec![
            PolicyLevel {
                owner: fp(10),
                policy: vault_policy,
            },
            PolicyLevel {
                owner: fp(11),
                policy: org_policy,
            },
        ];

        // Admin can manage policy (highest role wins over vault-level ReadOnly)
        let req = make_request(member, AccessAction::ManagePolicy, "dev");
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn test_owner_at_org_level_allowed() {
        let org_owner = fp(5);
        let chain = vec![
            PolicyLevel {
                owner: fp(10),
                policy: VaultPolicy::new(),
            },
            PolicyLevel {
                owner: org_owner.clone(),
                policy: VaultPolicy::new(),
            },
        ];
        let req = make_request(org_owner, AccessAction::ManagePolicy, "prod");
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn test_env_union() {
        let member = fp(2);

        let mut vault_policy = VaultPolicy::new();
        let mut vp = MemberPolicy::new(member.clone(), Role::Contributor);
        vp.allowed_envs = vec!["dev".into()];
        vault_policy.add_member(vp);

        let mut org_policy = VaultPolicy::new();
        let mut op = MemberPolicy::new(member.clone(), Role::Contributor);
        op.allowed_envs = vec!["staging".into(), "prod".into()];
        org_policy.add_member(op);

        let chain = vec![
            PolicyLevel {
                owner: fp(10),
                policy: vault_policy,
            },
            PolicyLevel {
                owner: fp(11),
                policy: org_policy,
            },
        ];

        // Can access dev (from vault level)
        let req = make_request(member.clone(), AccessAction::Read, "dev");
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );

        // Can access prod (from org level)
        let req = make_request(member.clone(), AccessAction::Read, "prod");
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );

        // Cannot access unknown env
        let req = make_request(member, AccessAction::Read, "custom");
        assert!(matches!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn test_env_wildcard_union() {
        let member = fp(2);

        let mut vault_policy = VaultPolicy::new();
        let mut vp = MemberPolicy::new(member.clone(), Role::Contributor);
        vp.allowed_envs = vec!["dev".into()];
        vault_policy.add_member(vp);

        let mut org_policy = VaultPolicy::new();
        let mut op = MemberPolicy::new(member.clone(), Role::Contributor);
        op.allowed_envs = vec!["*".into()];
        org_policy.add_member(op);

        let chain = vec![
            PolicyLevel {
                owner: fp(10),
                policy: vault_policy,
            },
            PolicyLevel {
                owner: fp(11),
                policy: org_policy,
            },
        ];

        // Wildcard from org level grants access to any env
        let req = make_request(member, AccessAction::Read, "anything");
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn test_pattern_union() {
        let member = fp(2);

        let mut vault_policy = VaultPolicy::new();
        let mut vp = MemberPolicy::new(member.clone(), Role::Contributor);
        vp.secret_patterns = vec!["DB_*".into()];
        vault_policy.add_member(vp);

        let mut org_policy = VaultPolicy::new();
        let mut op = MemberPolicy::new(member.clone(), Role::Contributor);
        op.secret_patterns = vec!["API_*".into()];
        org_policy.add_member(op);

        let chain = vec![
            PolicyLevel {
                owner: fp(10),
                policy: vault_policy,
            },
            PolicyLevel {
                owner: fp(11),
                policy: org_policy,
            },
        ];

        // Can access DB_* (from vault)
        let mut req = make_request(member.clone(), AccessAction::Read, "dev");
        req.key = Some("DB_URL".into());
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );

        // Can access API_* (from org)
        let mut req = make_request(member.clone(), AccessAction::Read, "dev");
        req.key = Some("API_KEY".into());
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );

        // Cannot access SSH_*
        let mut req = make_request(member, AccessAction::Read, "dev");
        req.key = Some("SSH_KEY".into());
        assert!(matches!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn test_operator_cannot_read_even_at_org_level() {
        let member = fp(2);

        let mut org_policy = VaultPolicy::new();
        org_policy.add_member(MemberPolicy::new(member.clone(), Role::Operator));

        let chain = vec![PolicyLevel {
            owner: fp(10),
            policy: org_policy,
        }];

        let req = make_request(member, AccessAction::Read, "dev");
        assert!(matches!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn test_member_only_at_org_level_can_access_vault() {
        let member = fp(2);

        // No membership at vault level
        let vault_policy = VaultPolicy::new();

        // Admin at org level
        let mut org_policy = VaultPolicy::new();
        org_policy.add_member(MemberPolicy::new(member.clone(), Role::Admin));

        let chain = vec![
            PolicyLevel {
                owner: fp(10),
                policy: vault_policy,
            },
            PolicyLevel {
                owner: fp(11),
                policy: org_policy,
            },
        ];

        let req = make_request(member, AccessAction::Read, "dev");
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );
    }
}
