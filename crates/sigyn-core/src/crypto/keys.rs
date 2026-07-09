use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, SigynError};

#[derive(Clone, Serialize, Deserialize, PartialOrd, Ord)]
pub struct KeyFingerprint(pub [u8; 16]);

impl PartialEq for KeyFingerprint {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for KeyFingerprint {}

impl std::hash::Hash for KeyFingerprint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl KeyFingerprint {
    pub fn from_pubkey(pubkey: &X25519PublicKey) -> Self {
        let hash = blake3::hash(pubkey.as_bytes());
        let mut fp = [0u8; 16];
        fp.copy_from_slice(&hash.as_bytes()[..16]);
        Self(fp)
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex_decode(s).map_err(|e| SigynError::InvalidKey(e.to_string()))?;
        if bytes.len() != 16 {
            return Err(SigynError::InvalidKey(
                "fingerprint must be 16 bytes".into(),
            ));
        }
        let mut fp = [0u8; 16];
        fp.copy_from_slice(&bytes);
        Ok(Self(fp))
    }
}

impl std::fmt::Debug for KeyFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyFingerprint({})", self.to_hex())
    }
}

impl std::fmt::Display for KeyFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> std::result::Result<Vec<u8>, String> {
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    // Decode over raw bytes: slicing a &str by byte offset panics on multi-byte
    // UTF-8 characters, and from_str_radix is too lenient (accepts leading '+').
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("odd length hex string".into());
    }
    bytes
        .chunks_exact(2)
        .map(|pair| match (nibble(pair[0]), nibble(pair[1])) {
            (Some(hi), Some(lo)) => Ok((hi << 4) | lo),
            _ => Err("invalid hex character".to_string()),
        })
        .collect()
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519PrivateKey {
    bytes: [u8; 32],
}

impl X25519PrivateKey {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        Self {
            bytes: secret.to_bytes(),
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn public_key(&self) -> X25519PublicKey {
        let secret = StaticSecret::from(self.bytes);
        let public = PublicKey::from(&secret);
        X25519PublicKey(*public.as_bytes())
    }

    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> [u8; 32] {
        let secret = StaticSecret::from(self.bytes);
        let public = PublicKey::from(their_public.0);
        *secret.diffie_hellman(&public).as_bytes()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct X25519PublicKey(pub [u8; 32]);

impl X25519PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn fingerprint(&self) -> KeyFingerprint {
        KeyFingerprint::from_pubkey(self)
    }
}

impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519PublicKey({})", self.fingerprint())
    }
}

pub struct SigningKeyPair {
    signing_key: SigningKey,
}

impl Drop for SigningKeyPair {
    fn drop(&mut self) {
        // ed25519-dalek SigningKey implements ZeroizeOnDrop, so replacement
        // with a zeroed key ensures the original key material is overwritten
        // immediately rather than waiting for the inner drop.
        let zero_key = SigningKey::from_bytes(&[0u8; 32]);
        // Overwrite in place by swapping
        let _ = std::mem::replace(&mut self.signing_key, zero_key);
    }
}

impl SigningKeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKeyWrapper {
        VerifyingKeyWrapper(self.signing_key.verifying_key())
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VerifyingKeyWrapper(#[serde(with = "verifying_key_serde")] pub VerifyingKey);

impl std::fmt::Debug for VerifyingKeyWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VerifyingKey({:?})", &self.0.to_bytes()[..8])
    }
}

impl VerifyingKeyWrapper {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let sig =
            Signature::from_slice(signature).map_err(|_| SigynError::SignatureVerification)?;
        self.0
            .verify(message, &sig)
            .map_err(|_| SigynError::SignatureVerification)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        VerifyingKey::from_bytes(bytes)
            .map(VerifyingKeyWrapper)
            .map_err(|e| SigynError::InvalidKey(e.to_string()))
    }
}

mod verifying_key_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        key: &VerifyingKey,
        ser: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        ser.serialize_bytes(&key.to_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> std::result::Result<VerifyingKey, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(de)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
        VerifyingKey::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation_and_fingerprint() {
        let private = X25519PrivateKey::generate();
        let public = private.public_key();
        let fp = public.fingerprint();
        assert_eq!(fp.to_hex().len(), 32);
    }

    #[test]
    fn test_diffie_hellman() {
        let alice = X25519PrivateKey::generate();
        let bob = X25519PrivateKey::generate();
        let shared1 = alice.diffie_hellman(&bob.public_key());
        let shared2 = bob.diffie_hellman(&alice.public_key());
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_signing() {
        let kp = SigningKeyPair::generate();
        let msg = b"hello world";
        let sig = kp.sign(msg);
        assert!(kp.verifying_key().verify(msg, &sig).is_ok());
        assert!(kp.verifying_key().verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn test_fingerprint_roundtrip() {
        let private = X25519PrivateKey::generate();
        let fp = private.public_key().fingerprint();
        let hex = fp.to_hex();
        let fp2 = KeyFingerprint::from_hex(&hex).unwrap();
        assert_eq!(fp, fp2);
    }

    #[test]
    fn test_from_hex_rejects_multibyte_utf8() {
        // Must return Err rather than panic on a UTF-8 char boundary
        // ("€" is 3 bytes, so "€€" has even byte length and reaches decoding).
        assert!(KeyFingerprint::from_hex("€€").is_err());
        assert!(KeyFingerprint::from_hex(&"€".repeat(16)).is_err());
        assert!(KeyFingerprint::from_hex("aé").is_err());
    }

    #[test]
    fn test_from_hex_rejects_odd_length() {
        assert!(KeyFingerprint::from_hex("abc").is_err());
        assert!(KeyFingerprint::from_hex("a").is_err());
    }

    #[test]
    fn test_from_hex_rejects_non_hex_chars() {
        assert!(KeyFingerprint::from_hex(&"zz".repeat(16)).is_err());
        // from_str_radix would accept a leading '+'; strict decoding must not
        assert!(KeyFingerprint::from_hex(&"+1".repeat(16)).is_err());
        assert!(KeyFingerprint::from_hex(&" 1".repeat(16)).is_err());
    }

    #[test]
    fn test_from_hex_rejects_wrong_length() {
        // Valid hex but not 16 bytes
        assert!(KeyFingerprint::from_hex("aabb").is_err());
        assert!(KeyFingerprint::from_hex(&"ab".repeat(17)).is_err());
        assert!(KeyFingerprint::from_hex("").is_err());
    }

    #[test]
    fn test_from_hex_accepts_uppercase() {
        let fp = KeyFingerprint([0xABu8; 16]);
        let upper = fp.to_hex().to_uppercase();
        assert_eq!(KeyFingerprint::from_hex(&upper).unwrap(), fp);
    }
}
