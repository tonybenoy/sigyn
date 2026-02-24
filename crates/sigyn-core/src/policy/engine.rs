use super::acl::matches_secret_pattern;
use super::storage::VaultPolicy;
use crate::crypto::keys::KeyFingerprint;
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct AccessRequest {
    pub actor: KeyFingerprint,
    pub action: AccessAction,
    pub env: String,
    pub key: Option<String>,
    pub mfa_verified: bool,
}

#[derive(Debug, Clone)]
pub enum AccessAction {
    Read,
    Write,
    Delete,
    ManageMembers,
    ManagePolicy,
    CreateEnv,
    Promote,
    Audit,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny(String),
    AllowWithWarning(String),
    RequiresMfa,
}

pub struct PolicyEngine<'a> {
    policy: &'a VaultPolicy,
    owner: &'a KeyFingerprint,
}

impl<'a> PolicyEngine<'a> {
    pub fn new(policy: &'a VaultPolicy, owner: &'a KeyFingerprint) -> Self {
        Self { policy, owner }
    }

    pub fn evaluate(&self, request: &AccessRequest) -> Result<PolicyDecision> {
        if &request.actor == self.owner {
            return Ok(PolicyDecision::Allow);
        }

        let member = match self.policy.get_member(&request.actor) {
            Some(m) => m,
            None => return Ok(PolicyDecision::Deny("not a vault member".into())),
        };

        // Check global constraints first
        if let Some(global) = &self.policy.global_constraints {
            if let Err(reason) = global.check(chrono::Utc::now()) {
                return Ok(PolicyDecision::Deny(reason));
            }
        }

        // Check member-specific constraints
        if let Some(constraints) = &member.constraints {
            if let Err(reason) = constraints.check(chrono::Utc::now()) {
                return Ok(PolicyDecision::Deny(reason));
            }
        }

        if !member
            .allowed_envs
            .iter()
            .any(|e| e == "*" || e == &request.env)
        {
            return Ok(PolicyDecision::Deny(format!(
                "no access to env '{}'",
                request.env
            )));
        }

        match &request.action {
            AccessAction::Read => {
                if !member.role.can_read() {
                    return Ok(PolicyDecision::Deny("role cannot read".into()));
                }
            }
            AccessAction::Write | AccessAction::Delete => {
                if !member.role.can_write() {
                    return Ok(PolicyDecision::Deny("role cannot write".into()));
                }
            }
            AccessAction::ManageMembers => {
                if !member.role.can_manage_members() {
                    return Ok(PolicyDecision::Deny("role cannot manage members".into()));
                }
            }
            AccessAction::ManagePolicy => {
                if !member.role.can_manage_policy() {
                    return Ok(PolicyDecision::Deny("role cannot manage policy".into()));
                }
            }
            AccessAction::CreateEnv | AccessAction::Promote => {
                if !member.role.can_manage_members() {
                    return Ok(PolicyDecision::Deny(
                        "role cannot manage environments".into(),
                    ));
                }
            }
            AccessAction::Audit => {
                if !member.role.can_audit() {
                    return Ok(PolicyDecision::Deny("role cannot access audit logs".into()));
                }
            }
        }

        if let Some(key) = &request.key {
            if !matches_secret_pattern(key, &member.secret_patterns)? {
                return Ok(PolicyDecision::Deny(format!("no access to key '{}'", key)));
            }
        }

        // Check if access is expiring soon (within 24 hours) for AllowWithWarning
        let mut warning: Option<String> = None;
        let now = chrono::Utc::now();
        let warn_threshold = chrono::Duration::hours(24);
        if let Some(constraints) = &member.constraints {
            if let Some(expires_at) = constraints.expires_at {
                let remaining = expires_at - now;
                if remaining > chrono::Duration::zero() && remaining < warn_threshold {
                    warning = Some(format!("access expires in {} hours", remaining.num_hours()));
                }
            }
        }
        if warning.is_none() {
            if let Some(global) = &self.policy.global_constraints {
                if let Some(expires_at) = global.expires_at {
                    let remaining = expires_at - now;
                    if remaining > chrono::Duration::zero() && remaining < warn_threshold {
                        warning =
                            Some(format!("access expires in {} hours", remaining.num_hours()));
                    }
                }
            }
        }

        // Check MFA requirement from global or member constraints
        if !request.mfa_verified {
            let global_requires = self
                .policy
                .global_constraints
                .as_ref()
                .is_some_and(|c| c.require_mfa);
            let member_requires = member.constraints.as_ref().is_some_and(|c| c.require_mfa);
            if global_requires || member_requires {
                return Ok(PolicyDecision::RequiresMfa);
            }
        }

        if let Some(msg) = warning {
            Ok(PolicyDecision::AllowWithWarning(msg))
        } else {
            Ok(PolicyDecision::Allow)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::member::MemberPolicy;
    use crate::policy::roles::Role;

    #[test]
    fn test_owner_always_allowed() {
        let owner = KeyFingerprint([0u8; 16]);
        let policy = VaultPolicy::new();
        let engine = PolicyEngine::new(&policy, &owner);

        let request = AccessRequest {
            actor: owner.clone(),
            action: AccessAction::ManagePolicy,
            env: "prod".into(),
            key: None,

            mfa_verified: false,
        };
        assert_eq!(engine.evaluate(&request).unwrap(), PolicyDecision::Allow);
    }

    #[test]
    fn test_non_member_denied() {
        let owner = KeyFingerprint([0u8; 16]);
        let stranger = KeyFingerprint([1u8; 16]);
        let policy = VaultPolicy::new();
        let engine = PolicyEngine::new(&policy, &owner);

        let request = AccessRequest {
            actor: stranger,
            action: AccessAction::Read,
            env: "dev".into(),
            key: None,

            mfa_verified: false,
        };
        assert!(matches!(
            engine.evaluate(&request).unwrap(),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn test_operator_cannot_read() {
        let owner = KeyFingerprint([0u8; 16]);
        let operator = KeyFingerprint([3u8; 16]);
        let mut policy = VaultPolicy::new();
        policy.add_member(MemberPolicy::new(operator.clone(), Role::Operator));
        let engine = PolicyEngine::new(&policy, &owner);

        let read_req = AccessRequest {
            actor: operator,
            action: AccessAction::Read,
            env: "dev".into(),
            key: Some("DB_URL".into()),

            mfa_verified: false,
        };
        assert!(matches!(
            engine.evaluate(&read_req).unwrap(),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn test_auditor_can_audit() {
        let owner = KeyFingerprint([0u8; 16]);
        let auditor = KeyFingerprint([4u8; 16]);
        let mut policy = VaultPolicy::new();
        policy.add_member(MemberPolicy::new(auditor.clone(), Role::Auditor));
        let engine = PolicyEngine::new(&policy, &owner);

        let audit_req = AccessRequest {
            actor: auditor.clone(),
            action: AccessAction::Audit,
            env: "dev".into(),
            key: None,

            mfa_verified: false,
        };
        assert_eq!(engine.evaluate(&audit_req).unwrap(), PolicyDecision::Allow);

        // ReadOnly cannot audit
        let readonly = KeyFingerprint([5u8; 16]);
        policy.add_member(MemberPolicy::new(readonly.clone(), Role::ReadOnly));
        let engine = PolicyEngine::new(&policy, &owner);
        let audit_req = AccessRequest {
            actor: readonly,
            action: AccessAction::Audit,
            env: "dev".into(),
            key: None,

            mfa_verified: false,
        };
        assert!(matches!(
            engine.evaluate(&audit_req).unwrap(),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn test_readonly_cannot_write() {
        let owner = KeyFingerprint([0u8; 16]);
        let reader = KeyFingerprint([2u8; 16]);
        let mut policy = VaultPolicy::new();
        policy.add_member(MemberPolicy::new(reader.clone(), Role::ReadOnly));
        let engine = PolicyEngine::new(&policy, &owner);

        let read_req = AccessRequest {
            actor: reader.clone(),
            action: AccessAction::Read,
            env: "dev".into(),
            key: Some("DB_URL".into()),

            mfa_verified: false,
        };
        assert_eq!(engine.evaluate(&read_req).unwrap(), PolicyDecision::Allow);

        let write_req = AccessRequest {
            actor: reader,
            action: AccessAction::Write,
            env: "dev".into(),
            key: Some("DB_URL".into()),

            mfa_verified: false,
        };
        assert!(matches!(
            engine.evaluate(&write_req).unwrap(),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn test_env_restrictions() {
        let owner = KeyFingerprint([0u8; 16]);
        let member = KeyFingerprint([2u8; 16]);
        let mut policy = VaultPolicy::new();
        let mut member_policy = MemberPolicy::new(member.clone(), Role::Contributor);
        member_policy.allowed_envs = vec!["dev".into(), "staging".into()];
        policy.add_member(member_policy);

        let engine = PolicyEngine::new(&policy, &owner);

        // Allowed env
        let req = AccessRequest {
            actor: member.clone(),
            action: AccessAction::Read,
            env: "dev".into(),
            key: None,

            mfa_verified: false,
        };
        assert_eq!(engine.evaluate(&req).unwrap(), PolicyDecision::Allow);

        // Denied env
        let req = AccessRequest {
            actor: member.clone(),
            action: AccessAction::Read,
            env: "prod".into(),
            key: None,

            mfa_verified: false,
        };
        assert!(matches!(
            engine.evaluate(&req).unwrap(),
            PolicyDecision::Deny(_)
        ));
    }
}
