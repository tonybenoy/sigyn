use serde::{Deserialize, Serialize};

use super::profile::IdentityProfile;
use crate::crypto::kdf;
use crate::crypto::keys::VerifyingKeyWrapper;
use crate::crypto::keys::{KeyFingerprint, X25519PublicKey};
use crate::error::Result;

#[derive(Serialize, Deserialize)]
pub struct WrappedIdentity {
    pub fingerprint: KeyFingerprint,
    pub profile: IdentityProfile,
    pub encryption_pubkey: X25519PublicKey,
    pub signing_pubkey: VerifyingKeyWrapper,
    pub wrapped_encryption_key: Vec<u8>,
    pub wrapped_signing_key: Vec<u8>,
    pub salt: [u8; 32],
}

impl WrappedIdentity {
    pub fn wrap(
        encryption_private: &[u8; 32],
        signing_private: &[u8; 32],
        encryption_pubkey: X25519PublicKey,
        signing_pubkey: VerifyingKeyWrapper,
        profile: IdentityProfile,
        passphrase: &str,
    ) -> Result<Self> {
        let salt = crate::crypto::nonce::generate_salt();
        let wrapped_encryption = kdf::wrap_private_key(encryption_private, passphrase, &salt)?;
        let wrapped_signing = kdf::wrap_private_key(signing_private, passphrase, &salt)?;

        Ok(Self {
            fingerprint: encryption_pubkey.fingerprint(),
            profile,
            encryption_pubkey,
            signing_pubkey,
            wrapped_encryption_key: wrapped_encryption,
            wrapped_signing_key: wrapped_signing,
            salt,
        })
    }

    pub fn unwrap_encryption_key(&self, passphrase: &str) -> Result<[u8; 32]> {
        kdf::unwrap_private_key(&self.wrapped_encryption_key, passphrase, &self.salt)
    }

    pub fn unwrap_signing_key(&self, passphrase: &str) -> Result<[u8; 32]> {
        kdf::unwrap_private_key(&self.wrapped_signing_key, passphrase, &self.salt)
    }
}
