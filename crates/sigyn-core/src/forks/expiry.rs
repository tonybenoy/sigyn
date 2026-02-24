use super::types::{Fork, ForkStatus};

pub fn check_expiry(fork: &mut Fork) -> bool {
    if let Some(expires_at) = fork.expires_at {
        if chrono::Utc::now() > expires_at && matches!(fork.status, ForkStatus::Active) {
            fork.status = ForkStatus::Expired;
            return true;
        }
    }
    false
}

pub fn expire_fork(fork: &mut Fork) {
    fork.status = ForkStatus::Expired;
}

pub fn revoke_fork(fork: &mut Fork) {
    fork.status = ForkStatus::Revoked;
}

pub fn archive_fork(fork: &mut Fork) {
    fork.status = ForkStatus::Archived;
}

pub fn set_expiry(fork: &mut Fork, expires_at: chrono::DateTime<chrono::Utc>) {
    fork.expires_at = Some(expires_at);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyFingerprint;
    use crate::forks::types::{Fork, ForkMode, ForkPolicy, ForkSharingPolicy, ForkStatus};
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    fn create_test_fork() -> Fork {
        Fork {
            id: Uuid::new_v4(),
            parent_vault_id: Uuid::new_v4(),
            fork_vault_id: Uuid::new_v4(),
            mode: ForkMode::Leashed,
            status: ForkStatus::Active,
            policy: ForkPolicy {
                sharing: ForkSharingPolicy::Private,
                max_drift_days: None,
                inherit_revocations: true,
                allow_new_members: false,
            },
            created_by: KeyFingerprint([0u8; 16]),
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    #[test]
    fn test_expiry_logic() {
        let mut fork = create_test_fork();

        // No expiry set
        assert!(!check_expiry(&mut fork));
        assert!(matches!(fork.status, ForkStatus::Active));

        // Expiry in future
        fork.expires_at = Some(Utc::now() + Duration::hours(1));
        assert!(!check_expiry(&mut fork));
        assert!(matches!(fork.status, ForkStatus::Active));

        // Expiry in past
        fork.expires_at = Some(Utc::now() - Duration::hours(1));
        assert!(check_expiry(&mut fork));
        assert!(matches!(fork.status, ForkStatus::Expired));
    }

    #[test]
    fn test_status_helpers() {
        let mut fork = create_test_fork();

        expire_fork(&mut fork);
        assert!(matches!(fork.status, ForkStatus::Expired));

        revoke_fork(&mut fork);
        assert!(matches!(fork.status, ForkStatus::Revoked));

        archive_fork(&mut fork);
        assert!(matches!(fork.status, ForkStatus::Archived));
    }
}
