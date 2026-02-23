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
