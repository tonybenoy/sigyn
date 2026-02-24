use serde::{Deserialize, Serialize};

use crate::crypto::keys::KeyFingerprint;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub enum SecretAcl {
    #[default]
    Everyone,
    Roles(Vec<String>),
    Fingerprints(Vec<KeyFingerprint>),
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAcl {
    pub read: SecretAcl,
    pub write: SecretAcl,
}

impl Default for KeyAcl {
    fn default() -> Self {
        Self {
            read: SecretAcl::Everyone,
            write: SecretAcl::Everyone,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_acl_default() {
        let acl = SecretAcl::default();
        assert_eq!(acl, SecretAcl::Everyone);
    }

    #[test]
    fn test_key_acl_default() {
        let acl = KeyAcl::default();
        assert_eq!(acl.read, SecretAcl::Everyone);
        assert_eq!(acl.write, SecretAcl::Everyone);
    }

    #[test]
    fn test_secret_acl_variants() {
        let deny = SecretAcl::Deny;
        assert_ne!(deny, SecretAcl::Everyone);

        let roles = SecretAcl::Roles(vec!["admin".to_string()]);
        assert_ne!(roles, SecretAcl::Everyone);

        let fps = SecretAcl::Fingerprints(vec![KeyFingerprint([0xAA; 16])]);
        assert_ne!(fps, SecretAcl::Everyone);
    }

    #[test]
    fn test_key_acl_custom() {
        let acl = KeyAcl {
            read: SecretAcl::Roles(vec!["reader".to_string()]),
            write: SecretAcl::Deny,
        };
        assert_ne!(acl.read, SecretAcl::Everyone);
        assert_eq!(acl.write, SecretAcl::Deny);
    }
}
