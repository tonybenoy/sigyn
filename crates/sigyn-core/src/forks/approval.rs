use crate::crypto::keys::KeyFingerprint;
use crate::error::{Result, SigynError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForkApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkApproval {
    pub fork_id: uuid::Uuid,
    pub requested_by: KeyFingerprint,
    pub approved_by: Vec<KeyFingerprint>,
    pub rejected_by: Vec<KeyFingerprint>,
    pub status: ForkApprovalStatus,
    pub required_approvals: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// If set, the request can no longer be approved or rejected after this
    /// time. Defaults to `None` for backward compatibility with stored data.
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl ForkApproval {
    pub fn new(fork_id: uuid::Uuid, requested_by: KeyFingerprint, required: u32) -> Self {
        Self {
            fork_id,
            requested_by,
            approved_by: Vec::new(),
            rejected_by: Vec::new(),
            status: ForkApprovalStatus::Pending,
            required_approvals: required,
            created_at: chrono::Utc::now(),
            expires_at: None,
        }
    }

    /// Set an expiry deadline on the request.
    pub fn with_expiry(mut self, expires_at: chrono::DateTime<chrono::Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Transition a pending request to `Expired` if its deadline has passed.
    /// Returns true if the request is expired (whether just now or earlier).
    pub fn check_expiry(&mut self) -> bool {
        if matches!(self.status, ForkApprovalStatus::Pending) {
            if let Some(expires_at) = self.expires_at {
                if chrono::Utc::now() > expires_at {
                    self.status = ForkApprovalStatus::Expired;
                }
            }
        }
        matches!(self.status, ForkApprovalStatus::Expired)
    }

    /// Record an approval. Fails if the approver is the requester (no
    /// self-approval) or if the request is rejected or expired — both are
    /// terminal states. Approving an already-approved request is a no-op.
    pub fn approve(&mut self, approver: KeyFingerprint) -> Result<()> {
        self.check_expiry();
        match self.status {
            ForkApprovalStatus::Rejected => {
                return Err(SigynError::ForkNotPermitted(
                    "cannot approve a rejected fork request".into(),
                ));
            }
            ForkApprovalStatus::Expired => {
                return Err(SigynError::ForkNotPermitted(
                    "cannot approve an expired fork request".into(),
                ));
            }
            ForkApprovalStatus::Pending | ForkApprovalStatus::Approved => {}
        }
        if approver == self.requested_by {
            return Err(SigynError::ForkNotPermitted(
                "the requester cannot approve their own fork request".into(),
            ));
        }
        if !self.approved_by.contains(&approver) {
            self.approved_by.push(approver);
        }
        if self.approved_by.len() as u32 >= self.required_approvals {
            self.status = ForkApprovalStatus::Approved;
        }
        Ok(())
    }

    /// Record a rejection. Fails if the request is already approved or
    /// expired — both are terminal states. Rejecting an already-rejected
    /// request is a no-op (additional rejectors are recorded).
    pub fn reject(&mut self, rejector: KeyFingerprint) -> Result<()> {
        self.check_expiry();
        match self.status {
            ForkApprovalStatus::Approved => {
                return Err(SigynError::ForkNotPermitted(
                    "cannot reject an already-approved fork request".into(),
                ));
            }
            ForkApprovalStatus::Expired => {
                return Err(SigynError::ForkNotPermitted(
                    "cannot reject an expired fork request".into(),
                ));
            }
            ForkApprovalStatus::Pending | ForkApprovalStatus::Rejected => {}
        }
        if !self.rejected_by.contains(&rejector) {
            self.rejected_by.push(rejector);
        }
        self.status = ForkApprovalStatus::Rejected;
        Ok(())
    }

    pub fn is_approved(&self) -> bool {
        matches!(self.status, ForkApprovalStatus::Approved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_fork_approval_logic() {
        let fork_id = Uuid::new_v4();
        let requester = KeyFingerprint([1u8; 16]);
        let approver1 = KeyFingerprint([2u8; 16]);
        let approver2 = KeyFingerprint([3u8; 16]);

        let mut approval = ForkApproval::new(fork_id, requester, 2);
        assert!(!approval.is_approved());

        // First approval
        approval.approve(approver1.clone()).unwrap();
        assert!(!approval.is_approved());
        assert_eq!(approval.approved_by.len(), 1);

        // Duplicate approval should be idempotent
        approval.approve(approver1).unwrap();
        assert_eq!(approval.approved_by.len(), 1);

        // Second approval reaches threshold
        approval.approve(approver2).unwrap();
        assert!(approval.is_approved());
        assert!(matches!(approval.status, ForkApprovalStatus::Approved));
    }

    #[test]
    fn test_fork_rejection() {
        let mut approval = ForkApproval::new(Uuid::new_v4(), KeyFingerprint([1u8; 16]), 1);
        approval.reject(KeyFingerprint([2u8; 16])).unwrap();
        assert!(!approval.is_approved());
        assert!(matches!(approval.status, ForkApprovalStatus::Rejected));
    }

    #[test]
    fn test_rejection_is_terminal() {
        let requester = KeyFingerprint([1u8; 16]);
        let rejector = KeyFingerprint([2u8; 16]);
        let approver1 = KeyFingerprint([3u8; 16]);
        let approver2 = KeyFingerprint([4u8; 16]);

        let mut approval = ForkApproval::new(Uuid::new_v4(), requester, 1);
        approval.reject(rejector).unwrap();
        assert!(matches!(approval.status, ForkApprovalStatus::Rejected));

        // Approvals after rejection must fail and must not flip the status,
        // even once the approval count would reach the threshold.
        assert!(approval.approve(approver1).is_err());
        assert!(approval.approve(approver2).is_err());
        assert!(!approval.is_approved());
        assert!(matches!(approval.status, ForkApprovalStatus::Rejected));
        assert!(approval.approved_by.is_empty());

        // Re-rejecting a rejected request is an idempotent no-op.
        assert!(approval.reject(KeyFingerprint([5u8; 16])).is_ok());
        assert!(matches!(approval.status, ForkApprovalStatus::Rejected));
    }

    #[test]
    fn test_requester_cannot_self_approve() {
        let requester = KeyFingerprint([1u8; 16]);
        let mut approval = ForkApproval::new(Uuid::new_v4(), requester.clone(), 1);

        assert!(approval.approve(requester).is_err());
        assert!(!approval.is_approved());
        assert!(approval.approved_by.is_empty());
        assert!(matches!(approval.status, ForkApprovalStatus::Pending));
    }

    #[test]
    fn test_approval_is_terminal_for_reject() {
        let mut approval = ForkApproval::new(Uuid::new_v4(), KeyFingerprint([1u8; 16]), 1);
        approval.approve(KeyFingerprint([2u8; 16])).unwrap();
        assert!(approval.is_approved());

        assert!(approval.reject(KeyFingerprint([3u8; 16])).is_err());
        assert!(approval.is_approved());
        assert!(approval.rejected_by.is_empty());
    }

    #[test]
    fn test_expired_request_cannot_transition() {
        let requester = KeyFingerprint([1u8; 16]);
        let approver = KeyFingerprint([2u8; 16]);

        let mut approval = ForkApproval::new(Uuid::new_v4(), requester.clone(), 1)
            .with_expiry(chrono::Utc::now() - chrono::Duration::hours(1));

        assert!(approval.approve(approver.clone()).is_err());
        assert!(matches!(approval.status, ForkApprovalStatus::Expired));
        assert!(!approval.is_approved());
        assert!(approval.approved_by.is_empty());

        assert!(approval.reject(approver).is_err());
        assert!(matches!(approval.status, ForkApprovalStatus::Expired));
        assert!(approval.rejected_by.is_empty());
    }

    #[test]
    fn test_unexpired_request_can_transition() {
        let mut approval = ForkApproval::new(Uuid::new_v4(), KeyFingerprint([1u8; 16]), 1)
            .with_expiry(chrono::Utc::now() + chrono::Duration::hours(1));

        assert!(!approval.check_expiry());
        approval.approve(KeyFingerprint([2u8; 16])).unwrap();
        assert!(approval.is_approved());
    }

    #[test]
    fn test_check_expiry_only_expires_pending() {
        // An already-approved request does not become Expired retroactively.
        let mut approval = ForkApproval::new(Uuid::new_v4(), KeyFingerprint([1u8; 16]), 1)
            .with_expiry(chrono::Utc::now() + chrono::Duration::milliseconds(0));
        approval.status = ForkApprovalStatus::Approved;
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(!approval.check_expiry());
        assert!(matches!(approval.status, ForkApprovalStatus::Approved));
    }

    #[test]
    fn test_deserializes_without_expires_at() {
        // Stored approvals from before the expires_at field must still load.
        let json = format!(
            r#"{{"fork_id":"{}","requested_by":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"approved_by":[],"rejected_by":[],"status":"Pending","required_approvals":1,"created_at":"2026-01-01T00:00:00Z"}}"#,
            Uuid::new_v4()
        );
        let approval: ForkApproval = serde_json::from_str(&json).unwrap();
        assert!(approval.expires_at.is_none());
        assert!(matches!(approval.status, ForkApprovalStatus::Pending));
    }
}
