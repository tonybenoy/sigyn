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
