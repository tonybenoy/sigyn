use crate::crypto::keys::KeyFingerprint;
use crate::error::Result;
use crate::policy::acl::matches_secret_pattern;
use crate::policy::engine::{format_expiry_warning, AccessAction, AccessRequest, PolicyDecision};
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
/// 3. Restrictions from every level apply: member/global constraint
///    violations at any level deny, and MFA required at any level applies
/// 4. Grants are per-level and atomic: some single level's (role,
///    allowed_envs, secret_patterns) must permit the request on its own.
///    The role from one level is never combined with the env/pattern scope
///    of another level.
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

        // 3. Restrictions apply across all levels — any member-level
        //    constraint violation denies
        let now = chrono::Utc::now();
        for m in &member_entries {
            if let Some(constraints) = &m.constraints {
                if let Err(reason) = constraints.check(now) {
                    return Ok(PolicyDecision::Deny(reason));
                }
            }
        }

        // ... as does any global constraint violation at any level
        for level in chain {
            if let Some(global) = &level.policy.global_constraints {
                if let Err(reason) = global.check(now) {
                    return Ok(PolicyDecision::Deny(reason));
                }
            }
        }

        // 4. Grants are atomic per level: a single level must permit the
        //    request with its own role, env scope, and secret patterns.
        let mut first_denial: Option<String> = None;
        let mut granted = false;
        for m in &member_entries {
            match Self::level_denial(m, request)? {
                None => {
                    granted = true;
                    break;
                }
                Some(reason) => {
                    // Report the vault-most level's reason (entries are
                    // ordered vault → root org).
                    first_denial.get_or_insert(reason);
                }
            }
        }
        if !granted {
            // safe: member_entries is non-empty, so first_denial is Some
            return Ok(PolicyDecision::Deny(first_denial.unwrap()));
        }

        // 5. Check per-action MFA requirement from any level
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

        // 6. Check for expiring access (warning) — member constraints first,
        //    then global constraints at any level (parity with PolicyEngine)
        let warn_threshold = chrono::Duration::hours(24);
        for m in &member_entries {
            if let Some(constraints) = &m.constraints {
                if let Some(expires_at) = constraints.expires_at {
                    let remaining = expires_at - now;
                    if remaining > chrono::Duration::zero() && remaining < warn_threshold {
                        return Ok(PolicyDecision::AllowWithWarning(format_expiry_warning(
                            remaining,
                        )));
                    }
                }
            }
        }
        for level in chain {
            if let Some(global) = &level.policy.global_constraints {
                if let Some(expires_at) = global.expires_at {
                    let remaining = expires_at - now;
                    if remaining > chrono::Duration::zero() && remaining < warn_threshold {
                        return Ok(PolicyDecision::AllowWithWarning(format_expiry_warning(
                            remaining,
                        )));
                    }
                }
            }
        }

        Ok(PolicyDecision::Allow)
    }

    /// Check whether a single level's member policy grants the request on
    /// its own. Returns `None` when granted, or `Some(reason)` when denied.
    fn level_denial(member: &MemberPolicy, request: &AccessRequest) -> Result<Option<String>> {
        // Env scoping only applies to env-scoped actions; vault-wide
        // administrative actions must not be blocked by the current env.
        if !request.action.is_env_agnostic()
            && !member
                .allowed_envs
                .iter()
                .any(|e| e == "*" || e == &request.env)
        {
            return Ok(Some(format!("no access to env '{}'", request.env)));
        }

        match &request.action {
            AccessAction::Read => {
                if !member.role.can_read() {
                    return Ok(Some("role cannot read".into()));
                }
            }
            AccessAction::Write | AccessAction::Delete => {
                if !member.role.can_write() {
                    return Ok(Some("role cannot write".into()));
                }
            }
            AccessAction::ManageMembers => {
                if !member.role.can_manage_members() {
                    return Ok(Some("role cannot manage members".into()));
                }
            }
            AccessAction::ManagePolicy => {
                if !member.role.can_manage_policy() {
                    return Ok(Some("role cannot manage policy".into()));
                }
            }
            AccessAction::CreateEnv | AccessAction::Promote => {
                if !member.role.can_manage_members() {
                    return Ok(Some(
                        "role cannot create or promote environments (requires manager or higher)"
                            .into(),
                    ));
                }
            }
            AccessAction::Audit => {
                if !member.role.can_audit() {
                    return Ok(Some("role cannot access audit logs".into()));
                }
            }
        }

        match &request.key {
            Some(key) => {
                if !matches_secret_pattern(key, &member.secret_patterns)? {
                    return Ok(Some(format!("no access to key '{}'", key)));
                }
            }
            // A keyless data request (list/search/run/export/import/…)
            // touches every key in the environment, so it is only allowed
            // when this level's pattern set is unrestricted.
            None if request.action.accesses_secret_data() => {
                if !member.secret_patterns.iter().any(|p| p == "*") {
                    return Ok(Some(
                        "bulk access to all keys requires unrestricted secret patterns".into(),
                    ));
                }
            }
            None => {}
        }

        Ok(None)
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
    fn test_no_cross_level_grant_amplification() {
        let member = fp(2);

        // Vault level: ReadOnly, scoped to prod
        let mut vault_policy = VaultPolicy::new();
        let mut vp = MemberPolicy::new(member.clone(), Role::ReadOnly);
        vp.allowed_envs = vec!["prod".into()];
        vault_policy.add_member(vp);

        // Org level: Admin, scoped to dev
        let mut org_policy = VaultPolicy::new();
        let mut op = MemberPolicy::new(member.clone(), Role::Admin);
        op.allowed_envs = vec!["dev".into()];
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

        // Write prod: vault level is ReadOnly (no write), org level has no
        // prod access — combining Admin role with prod env must NOT be
        // possible
        let mut req = make_request(member.clone(), AccessAction::Write, "prod");
        req.key = Some("DB_URL".into());
        assert!(matches!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Deny(_)
        ));

        // Write dev: org level alone permits this (Admin + dev)
        let mut req = make_request(member.clone(), AccessAction::Write, "dev");
        req.key = Some("DB_URL".into());
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );

        // Read prod: vault level alone permits this (ReadOnly + prod)
        let mut req = make_request(member, AccessAction::Read, "prod");
        req.key = Some("DB_URL".into());
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn test_no_cross_level_role_pattern_amplification() {
        let member = fp(2);

        // Vault level: Contributor restricted to DB_*
        let mut vault_policy = VaultPolicy::new();
        let mut vp = MemberPolicy::new(member.clone(), Role::Contributor);
        vp.secret_patterns = vec!["DB_*".into()];
        vault_policy.add_member(vp);

        // Org level: ReadOnly with unrestricted patterns
        let mut org_policy = VaultPolicy::new();
        org_policy.add_member(MemberPolicy::new(member.clone(), Role::ReadOnly));

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

        // Write API_KEY: vault level can write but not API_*; org level has
        // unrestricted patterns but cannot write — must not combine
        let mut req = make_request(member.clone(), AccessAction::Write, "dev");
        req.key = Some("API_KEY".into());
        assert!(matches!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Deny(_)
        ));

        // Read API_KEY: org level alone permits this
        let mut req = make_request(member, AccessAction::Read, "dev");
        req.key = Some("API_KEY".into());
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn test_bulk_access_requires_unrestricted_patterns_at_one_level() {
        let member = fp(2);

        // Vault level only: pattern-restricted Contributor
        let mut vault_policy = VaultPolicy::new();
        let mut vp = MemberPolicy::new(member.clone(), Role::Contributor);
        vp.secret_patterns = vec!["DB_*".into()];
        vault_policy.add_member(vp);

        let chain = vec![PolicyLevel {
            owner: fp(10),
            policy: vault_policy,
        }];

        // Bulk read (key: None) denied for pattern-restricted member
        let req = make_request(member.clone(), AccessAction::Read, "dev");
        assert!(matches!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Deny(_)
        ));

        // Adding an org level with unrestricted patterns (default) grants
        // bulk read via that level alone
        let mut org_policy = VaultPolicy::new();
        org_policy.add_member(MemberPolicy::new(member.clone(), Role::ReadOnly));
        let mut chain = chain;
        chain.push(PolicyLevel {
            owner: fp(11),
            policy: org_policy,
        });

        let req = make_request(member, AccessAction::Read, "dev");
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn test_env_agnostic_action_not_blocked_by_env_scope() {
        let member = fp(2);

        let mut policy = VaultPolicy::new();
        let mut mp = MemberPolicy::new(member.clone(), Role::Manager);
        mp.allowed_envs = vec!["staging".into()];
        policy.add_member(mp);

        let chain = vec![PolicyLevel {
            owner: fp(10),
            policy,
        }];

        // ManageMembers is vault-wide; the current env must not block it
        let req = make_request(member.clone(), AccessAction::ManageMembers, "dev");
        assert_eq!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Allow
        );

        // Env-scoped read is still restricted
        let req = make_request(member, AccessAction::Read, "dev");
        assert!(matches!(
            HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap(),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn test_global_expiry_warning_parity() {
        use crate::policy::constraints::{Constraints, MfaActions};

        let member = fp(2);

        let mut policy = VaultPolicy::new();
        policy.add_member(MemberPolicy::new(member.clone(), Role::ReadOnly));
        // Global constraints expiring in 30 minutes → warning in minutes
        policy.global_constraints = Some(Constraints {
            time_windows: vec![],
            expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(30)),
            mfa_actions: MfaActions::default(),
        });

        let chain = vec![PolicyLevel {
            owner: fp(10),
            policy,
        }];

        let mut req = make_request(member, AccessAction::Read, "dev");
        req.key = Some("DB_URL".into());
        match HierarchicalPolicyEngine::evaluate(&chain, &req).unwrap() {
            PolicyDecision::AllowWithWarning(msg) => {
                assert!(msg.contains("access expires in"), "got: {}", msg);
                assert!(msg.contains("minutes"), "expected minutes, got: {}", msg);
            }
            other => panic!("expected AllowWithWarning, got: {:?}", other),
        }
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
