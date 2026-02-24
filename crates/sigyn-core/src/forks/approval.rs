use crate::crypto::keys::KeyFingerprint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForkApprovalStatus {
    Pending,
    Approved,
    Rejected,
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
        }
    }

    pub fn approve(&mut self, approver: KeyFingerprint) {
        if !self.approved_by.contains(&approver) {
            self.approved_by.push(approver);
        }
        if self.approved_by.len() as u32 >= self.required_approvals {
            self.status = ForkApprovalStatus::Approved;
        }
    }

    pub fn reject(&mut self, rejector: KeyFingerprint) {
        if !self.rejected_by.contains(&rejector) {
            self.rejected_by.push(rejector);
        }
        self.status = ForkApprovalStatus::Rejected;
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
        approval.approve(approver1.clone());
        assert!(!approval.is_approved());
        assert_eq!(approval.approved_by.len(), 1);

        // Duplicate approval should be idempotent
        approval.approve(approver1);
        assert_eq!(approval.approved_by.len(), 1);

        // Second approval reaches threshold
        approval.approve(approver2);
        assert!(approval.is_approved());
        assert!(matches!(approval.status, ForkApprovalStatus::Approved));
    }

    #[test]
    fn test_fork_rejection() {
        let mut approval = ForkApproval::new(Uuid::new_v4(), KeyFingerprint([1u8; 16]), 1);
        approval.reject(KeyFingerprint([2u8; 16]));
        assert!(!approval.is_approved());
        assert!(matches!(approval.status, ForkApprovalStatus::Rejected));
    }
}
