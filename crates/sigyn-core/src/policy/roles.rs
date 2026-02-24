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
