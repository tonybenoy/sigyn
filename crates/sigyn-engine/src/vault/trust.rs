//! Device-pinned policy-signer trust anchor (finding C1), shared by every
//! surface that unlocks a vault (CLI and web).
//!
//! A vault policy is signed by the owner or an admin. Because every member
//! holds the vault key, the authority of a *non-owner* signer must never be
//! taken from the freshly loaded policy itself — the signer could rewrite it to
//! grant themselves admin. Instead it is checked against a device-local record
//! of the admins in the last policy accepted on this device, kept in the
//! never-synced `pinned_vaults.cbor` store.
//!
//! This logic lived, duplicated, in the CLI and web unlock paths; the web copy
//! originally lagged the CLI, which is how C1 existed on the web side. Keeping
//! it here means both surfaces enforce the exact same rule.

use std::collections::HashMap;
use std::path::Path;

use sigyn_core::crypto::keys::KeyFingerprint;
use sigyn_core::error::{Result, SigynError};
use sigyn_core::policy::storage::VaultPolicy;
use sigyn_core::vault::local_state::PolicyTrustAnchor;

/// Enforce the trust anchor for a policy that has already had its signature
/// verified (so `policy_signer_fp` is the fingerprint whose key validated it).
///
/// Owner-signed policies refresh the recorded admin set. A non-owner
/// ("admin-signed") policy is accepted only if its signer was an admin in the
/// recorded set, and it may not add or elevate Admin+ members. Returns
/// [`SigynError::AccessDenied`] when the policy is rejected (callers should
/// surface this as a forbidden/authorization error) and other error variants on
/// device-key / local-state I/O failure (fail closed).
pub fn enforce_policy_trust_anchor(
    sigyn_home: &Path,
    vault_name: &str,
    owner: &KeyFingerprint,
    policy: &VaultPolicy,
    policy_signer_fp: &KeyFingerprint,
) -> Result<()> {
    let admin_signers: HashMap<String, u8> = policy
        .members
        .iter()
        .filter(|(_, m)| m.role.can_manage_policy())
        .map(|(fp_hex, m)| (fp_hex.clone(), m.role.level()))
        .collect();

    let device_key = crate::device::load_or_create_device_key(sigyn_home)?;
    let mut store = crate::vault::local_state::load_pinned_store(sigyn_home, &device_key)?;

    if policy_signer_fp == owner {
        // Owner-signed: (re)pin the owner-approved admin set.
        store.entry_mut(vault_name).policy_anchor = Some(PolicyTrustAnchor {
            admin_signers,
            updated_at: chrono::Utc::now(),
        });
        let _ = crate::vault::local_state::save_pinned_store(&store, sigyn_home, &device_key);
        return Ok(());
    }

    let state = store.entry_mut(vault_name);
    match &state.policy_anchor {
        Some(anchor) => {
            let signer_hex = policy_signer_fp.to_hex();
            if !anchor.admin_signers.contains_key(&signer_hex) {
                return Err(SigynError::AccessDenied(format!(
                    "policy signed by {} who was not an admin in the last policy accepted on \
                     this device — possible privilege escalation. If this admin was legitimately \
                     promoted, have the vault owner re-sign the policy.",
                    signer_hex
                )));
            }
            for (fp_hex, level) in &admin_signers {
                match anchor.admin_signers.get(fp_hex) {
                    Some(anchored_level) if level <= anchored_level => {}
                    _ => {
                        return Err(SigynError::AccessDenied(format!(
                            "policy signed by admin {} adds or elevates privileged member {} — \
                             only an owner-signed policy may change the admin set",
                            signer_hex, fp_hex
                        )));
                    }
                }
            }
        }
        None => {
            // First access with an admin-signed policy: TOFU-pin the admin set.
        }
    }

    // Anchor the (validated or first-seen) admin set for the next access.
    state.policy_anchor = Some(PolicyTrustAnchor {
        admin_signers,
        updated_at: chrono::Utc::now(),
    });
    let _ = crate::vault::local_state::save_pinned_store(&store, sigyn_home, &device_key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigyn_core::policy::member::MemberPolicy;
    use sigyn_core::policy::roles::Role;

    fn fp(b: u8) -> KeyFingerprint {
        KeyFingerprint([b; 16])
    }

    fn policy_with_admin(admin: &KeyFingerprint) -> VaultPolicy {
        let mut p = VaultPolicy::new();
        p.add_member(MemberPolicy::new(admin.clone(), Role::Admin));
        p
    }

    #[test]
    fn owner_signed_pins_and_admin_signed_is_then_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let owner = fp(1);
        let admin = fp(2);
        let policy = policy_with_admin(&admin);

        // Owner-signed policy records the admin set.
        enforce_policy_trust_anchor(home, "v", &owner, &policy, &owner).unwrap();
        // A subsequent policy signed by that admin is trusted.
        enforce_policy_trust_anchor(home, "v", &owner, &policy, &admin).unwrap();
    }

    #[test]
    fn admin_not_in_anchor_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let owner = fp(1);
        let admin = fp(2);
        let rogue = fp(3);

        // Pin an admin set that does NOT include the rogue.
        enforce_policy_trust_anchor(home, "v", &owner, &policy_with_admin(&admin), &owner).unwrap();

        // A policy that makes the rogue an admin, signed by the rogue, is rejected.
        let rogue_policy = policy_with_admin(&rogue);
        let err =
            enforce_policy_trust_anchor(home, "v", &owner, &rogue_policy, &rogue).unwrap_err();
        assert!(matches!(err, SigynError::AccessDenied(_)));
    }

    #[test]
    fn admin_signed_cannot_add_new_admin() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let owner = fp(1);
        let admin = fp(2);
        let newcomer = fp(4);

        enforce_policy_trust_anchor(home, "v", &owner, &policy_with_admin(&admin), &owner).unwrap();

        // Admin-signed policy that elevates a newcomer to admin is rejected.
        let mut escalated = policy_with_admin(&admin);
        escalated.add_member(MemberPolicy::new(newcomer, Role::Admin));
        let err = enforce_policy_trust_anchor(home, "v", &owner, &escalated, &admin).unwrap_err();
        assert!(matches!(err, SigynError::AccessDenied(_)));
    }
}
