use serde::{Deserialize, Serialize};
use std::fmt;

/// Role hierarchy. Note: Operator (level 3) is above Auditor (level 2) in the
/// hierarchy but intentionally cannot read secrets — it is designed for CI/CD
/// pipelines that need write access without exposing secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Role {
    ReadOnly = 1,
    Auditor = 2,
    Operator = 3,
    Contributor = 4,
    Manager = 5,
    Admin = 6,
    Owner = 7,
}

impl Role {
    pub fn level(&self) -> u8 {
        *self as u8
    }

    pub fn can_read(&self) -> bool {
        !matches!(self, Role::Operator)
    }

    pub fn can_audit(&self) -> bool {
        *self >= Role::Auditor
    }

    pub fn can_write(&self) -> bool {
        *self >= Role::Contributor
    }

    pub fn can_manage_members(&self) -> bool {
        *self >= Role::Manager
    }

    pub fn can_manage_policy(&self) -> bool {
        *self >= Role::Admin
    }

    pub fn can_delegate(&self) -> bool {
        *self >= Role::Manager
    }

    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "readonly" | "read-only" => Some(Role::ReadOnly),
            "auditor" => Some(Role::Auditor),
            "operator" => Some(Role::Operator),
            "contributor" => Some(Role::Contributor),
            "manager" => Some(Role::Manager),
            "admin" => Some(Role::Admin),
            "owner" => Some(Role::Owner),
            _ => None,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::ReadOnly => write!(f, "readonly"),
            Role::Auditor => write!(f, "auditor"),
            Role::Operator => write!(f, "operator"),
            Role::Contributor => write!(f, "contributor"),
            Role::Manager => write!(f, "manager"),
            Role::Admin => write!(f, "admin"),
            Role::Owner => write!(f, "owner"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_levels() {
        assert_eq!(Role::ReadOnly.level(), 1);
        assert_eq!(Role::Auditor.level(), 2);
        assert_eq!(Role::Operator.level(), 3);
        assert_eq!(Role::Contributor.level(), 4);
        assert_eq!(Role::Manager.level(), 5);
        assert_eq!(Role::Admin.level(), 6);
        assert_eq!(Role::Owner.level(), 7);
    }

    #[test]
    fn test_can_read() {
        assert!(Role::ReadOnly.can_read());
        assert!(Role::Auditor.can_read());
        assert!(!Role::Operator.can_read()); // Operator cannot read secrets
        assert!(Role::Contributor.can_read());
        assert!(Role::Manager.can_read());
        assert!(Role::Admin.can_read());
        assert!(Role::Owner.can_read());
    }

    #[test]
    fn test_can_audit() {
        assert!(!Role::ReadOnly.can_audit());
        assert!(Role::Auditor.can_audit());
        assert!(Role::Operator.can_audit());
        assert!(Role::Contributor.can_audit());
        assert!(Role::Manager.can_audit());
        assert!(Role::Admin.can_audit());
        assert!(Role::Owner.can_audit());
    }

    #[test]
    fn test_can_write() {
        assert!(!Role::ReadOnly.can_write());
        assert!(!Role::Auditor.can_write());
        assert!(!Role::Operator.can_write());
        assert!(Role::Contributor.can_write());
        assert!(Role::Manager.can_write());
        assert!(Role::Admin.can_write());
        assert!(Role::Owner.can_write());
    }

    #[test]
    fn test_can_manage_members() {
        assert!(!Role::ReadOnly.can_manage_members());
        assert!(!Role::Auditor.can_manage_members());
        assert!(!Role::Operator.can_manage_members());
        assert!(!Role::Contributor.can_manage_members());
        assert!(Role::Manager.can_manage_members());
        assert!(Role::Admin.can_manage_members());
        assert!(Role::Owner.can_manage_members());
    }

    #[test]
    fn test_can_manage_policy() {
        assert!(!Role::ReadOnly.can_manage_policy());
        assert!(!Role::Auditor.can_manage_policy());
        assert!(!Role::Operator.can_manage_policy());
        assert!(!Role::Contributor.can_manage_policy());
        assert!(!Role::Manager.can_manage_policy());
        assert!(Role::Admin.can_manage_policy());
        assert!(Role::Owner.can_manage_policy());
    }

    #[test]
    fn test_can_delegate() {
        assert!(!Role::ReadOnly.can_delegate());
        assert!(!Role::Auditor.can_delegate());
        assert!(!Role::Operator.can_delegate());
        assert!(!Role::Contributor.can_delegate());
        assert!(Role::Manager.can_delegate());
        assert!(Role::Admin.can_delegate());
        assert!(Role::Owner.can_delegate());
    }

    #[test]
    fn test_from_str_name() {
        assert_eq!(Role::from_str_name("readonly"), Some(Role::ReadOnly));
        assert_eq!(Role::from_str_name("read-only"), Some(Role::ReadOnly));
        assert_eq!(Role::from_str_name("ReadOnly"), Some(Role::ReadOnly));
        assert_eq!(Role::from_str_name("auditor"), Some(Role::Auditor));
        assert_eq!(Role::from_str_name("operator"), Some(Role::Operator));
        assert_eq!(Role::from_str_name("contributor"), Some(Role::Contributor));
        assert_eq!(Role::from_str_name("manager"), Some(Role::Manager));
        assert_eq!(Role::from_str_name("admin"), Some(Role::Admin));
        assert_eq!(Role::from_str_name("ADMIN"), Some(Role::Admin));
        assert_eq!(Role::from_str_name("owner"), Some(Role::Owner));
        assert_eq!(Role::from_str_name("invalid"), None);
        assert_eq!(Role::from_str_name(""), None);
    }

    #[test]
    fn test_display() {
        assert_eq!(Role::ReadOnly.to_string(), "readonly");
        assert_eq!(Role::Auditor.to_string(), "auditor");
        assert_eq!(Role::Operator.to_string(), "operator");
        assert_eq!(Role::Contributor.to_string(), "contributor");
        assert_eq!(Role::Manager.to_string(), "manager");
        assert_eq!(Role::Admin.to_string(), "admin");
        assert_eq!(Role::Owner.to_string(), "owner");
    }

    #[test]
    fn test_display_roundtrip() {
        let roles = [
            Role::ReadOnly,
            Role::Auditor,
            Role::Operator,
            Role::Contributor,
            Role::Manager,
            Role::Admin,
            Role::Owner,
        ];
        for role in roles {
            let name = role.to_string();
            assert_eq!(Role::from_str_name(&name), Some(role));
        }
    }
}
