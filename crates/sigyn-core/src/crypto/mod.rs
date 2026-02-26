pub mod envelope;
pub mod kdf;
pub mod keys;
pub mod nonce;
pub mod sealed;
pub mod vault_cipher;

pub use envelope::{EnvelopeHeader, RecipientSlot};
pub use kdf::{unwrap_private_key, wrap_private_key};
pub use keys::{KeyFingerprint, SigningKeyPair, X25519PrivateKey, X25519PublicKey};
pub use nonce::generate_nonce;
pub use vault_cipher::VaultCipher;
