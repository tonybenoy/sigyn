use serde::{Deserialize, Serialize};

use super::profile::IdentityProfile;
use crate::crypto::keys::{
    KeyFingerprint, SigningKeyPair, VerifyingKeyWrapper, X25519PrivateKey, X25519PublicKey,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub fingerprint: KeyFingerprint,
    pub profile: IdentityProfile,
    pub encryption_pubkey: X25519PublicKey,
    pub signing_pubkey: VerifyingKeyWrapper,
}

pub struct LoadedIdentity {
    pub identity: Identity,
    encryption_key: X25519PrivateKey,
    signing_key: SigningKeyPair,
}

impl LoadedIdentity {
    pub fn new(
        identity: Identity,
        encryption_key: X25519PrivateKey,
        signing_key: SigningKeyPair,
    ) -> Self {
        Self {
            identity,
            encryption_key,
            signing_key,
        }
    }

    pub fn encryption_key(&self) -> &X25519PrivateKey {
        &self.encryption_key
    }

    pub fn signing_key(&self) -> &SigningKeyPair {
        &self.signing_key
    }

    pub fn fingerprint(&self) -> &KeyFingerprint {
        &self.identity.fingerprint
    }
}
