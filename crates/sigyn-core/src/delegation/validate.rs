use crate::crypto::keys::KeyFingerprint;
use crate::error::{Result, SigynError};
use crate::policy::roles::Role;
use crate::policy::storage::VaultPolicy;

/// Validate that a delegation is permitted by the policy.
///
/// Checks:
/// - Inviter exists in the policy
/// - Inviter has remaining delegation depth (`max_delegation_depth > 0`)
/// - Inviter has not exceeded their delegatee limit (`max_delegatees`)
/// - Invitee role is strictly lower than inviter role
/// - Delegation chain is intact (inviter's delegator is still a member or the owner)
pub fn validate_delegation(
    policy: &VaultPolicy,
    inviter_fp: &KeyFingerprint,
    invitee_role: Role,
    owner_fp: Option<&KeyFingerprint>,
) -> Result<()> {
    let inviter = policy
        .get_member(inviter_fp)
        .ok_or_else(|| SigynError::MemberNotFound(inviter_fp.to_hex()))?;

    if inviter.max_delegation_depth == 0 {
        return Err(SigynError::DelegationDepthExceeded {
            max: 0,
            attempted: 1,
        });
    }

    // Count current delegatees of this inviter
    let delegatee_count = policy
        .members()
        .filter(|m| m.delegated_by.as_ref() == Some(inviter_fp))
        .count() as u32;
    if delegatee_count >= inviter.max_delegatees {
        return Err(SigynError::PolicyViolation(format!(
            "inviter has reached max delegatees limit ({})",
            inviter.max_delegatees
        )));
    }

    // Invitee role must be strictly lower than inviter role
    if invitee_role.level() >= inviter.role.level() {
        return Err(SigynError::PolicyViolation(format!(
            "cannot delegate role {} (level {}) — inviter role {} (level {})",
            invitee_role,
            invitee_role.level(),
            inviter.role,
            inviter.role.level()
        )));
    }

    // If the inviter was themselves delegated, verify the delegation chain integrity:
    // the inviter's delegated_by must point to a valid member OR the vault owner.
    // The owner is not stored in the policy members list — it's in the manifest.
    if let Some(ref delegator_fp) = inviter.delegated_by {
        let is_owner = owner_fp.is_some_and(|ofp| ofp == delegator_fp);
        if !is_owner && policy.get_member(delegator_fp).is_none() {
            return Err(SigynError::PolicyViolation(format!(
                "inviter's delegator {} is not a current policy member — delegation chain broken",
                delegator_fp.to_hex()
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::member::MemberPolicy;

    fn test_fp(byte: u8) -> KeyFingerprint {
        KeyFingerprint([byte; 16])
    }

    #[test]
    fn test_valid_delegation() {
        let mut policy = VaultPolicy::new();
        let admin_fp = test_fp(0xAA);
        let mut admin = MemberPolicy::new(admin_fp.clone(), Role::Admin);
        admin.max_delegation_depth = 2;
        admin.max_delegatees = 10;
        policy.add_member(admin);

        assert!(validate_delegation(&policy, &admin_fp, Role::Contributor, None).is_ok());
    }

    #[test]
    fn test_inviter_not_found() {
        let policy = VaultPolicy::new();
        let fp = test_fp(0xBB);
        assert!(validate_delegation(&policy, &fp, Role::ReadOnly, None).is_err());
    }

    #[test]
    fn test_depth_zero_rejected() {
        let mut policy = VaultPolicy::new();
        let fp = test_fp(0xCC);
        let mut member = MemberPolicy::new(fp.clone(), Role::Admin);
        member.max_delegation_depth = 0;
        policy.add_member(member);

        let err = validate_delegation(&policy, &fp, Role::Contributor, None).unwrap_err();
        assert!(matches!(err, SigynError::DelegationDepthExceeded { .. }));
    }

    #[test]
    fn test_max_delegatees_exceeded() {
        let mut policy = VaultPolicy::new();
        let inviter_fp = test_fp(0xDD);
        let mut inviter = MemberPolicy::new(inviter_fp.clone(), Role::Admin);
        inviter.max_delegatees = 1;
        policy.add_member(inviter);

        // Add one existing delegatee
        let delegatee_fp = test_fp(0xEE);
        let mut delegatee = MemberPolicy::new(delegatee_fp, Role::Contributor);
        delegatee.delegated_by = Some(inviter_fp.clone());
        policy.add_member(delegatee);

        let err = validate_delegation(&policy, &inviter_fp, Role::ReadOnly, None).unwrap_err();
        assert!(matches!(err, SigynError::PolicyViolation(_)));
    }

    #[test]
    fn test_role_escalation_rejected() {
        let mut policy = VaultPolicy::new();
        let fp = test_fp(0xFF);
        let member = MemberPolicy::new(fp.clone(), Role::Manager);
        policy.add_member(member);

        // Same level
        let err = validate_delegation(&policy, &fp, Role::Manager, None).unwrap_err();
        assert!(matches!(err, SigynError::PolicyViolation(_)));

        // Higher level
        let err = validate_delegation(&policy, &fp, Role::Admin, None).unwrap_err();
        assert!(matches!(err, SigynError::PolicyViolation(_)));

        // Lower level — OK
        assert!(validate_delegation(&policy, &fp, Role::Contributor, None).is_ok());
    }
}
