use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigynError {
    // Crypto errors
    #[error("key generation failed: {0}")]
    KeyGeneration(String),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("no matching recipient slot found for this key")]
    NoMatchingSlot,
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("signature verification failed")]
    SignatureVerification,

    // Vault errors
    #[error("vault not accessible: {0}")]
    VaultNotFound(String),
    #[error("vault already exists: {0}")]
    VaultAlreadyExists(String),
    #[error("environment not accessible: {0}")]
    EnvironmentNotFound(String),
    #[error("environment already exists: {0}")]
    EnvironmentAlreadyExists(String),
    #[error("vault is locked")]
    VaultLocked,
    #[error("vault lock acquisition failed: {0}")]
    LockFailed(String),

    // Secret errors
    #[error("secret not found: {key} in env {env}")]
    SecretNotFound { key: String, env: String },
    #[error("secret validation failed: {0}")]
    ValidationFailed(String),
    #[error("invalid secret key name: {0}")]
    InvalidKeyName(String),

    // Identity errors
    #[error("identity not found: {0}")]
    IdentityNotFound(String),
    #[error("identity already exists: {0}")]
    IdentityAlreadyExists(String),
    #[error("invalid passphrase")]
    InvalidPassphrase,

    // MFA errors
    #[error("MFA not enrolled for identity {0}")]
    MfaNotEnrolled(String),
    #[error("MFA verification failed")]
    MfaVerificationFailed,
    #[error("MFA already enrolled for identity {0}")]
    MfaAlreadyEnrolled(String),

    // Policy errors
    #[error("access denied: {0}")]
    AccessDenied(String),
    #[error("insufficient role: required {required}, have {actual}")]
    InsufficientRole { required: String, actual: String },
    #[error("policy violation: {0}")]
    PolicyViolation(String),
    #[error("member not found: {0}")]
    MemberNotFound(String),

    // Hierarchy errors
    #[error("node not found: {0}")]
    NodeNotFound(String),
    #[error("node already exists: {0}")]
    NodeAlreadyExists(String),
    #[error("invalid org path: {0}")]
    InvalidOrgPath(String),
    #[error("hierarchy cycle detected: {0}")]
    HierarchyCycle(String),

    // Delegation errors
    #[error("invalid invitation: {0}")]
    InvalidInvitation(String),
    #[error("delegation depth exceeded: max {max}, attempted {attempted}")]
    DelegationDepthExceeded { max: u32, attempted: u32 },

    // Fork errors
    #[error("fork not found: {0}")]
    ForkNotFound(String),
    #[error("fork operation not permitted: {0}")]
    ForkNotPermitted(String),

    // Audit errors
    #[error("audit chain broken at sequence {0}")]
    AuditChainBroken(u64),
    #[error("audit signature invalid at sequence {0}")]
    AuditSignatureInvalid(u64),

    // Sync errors
    #[error("sync conflict on key {key} in env {env}")]
    SyncConflict { key: String, env: String },
    #[error("git operation failed: {0}")]
    GitError(String),

    // Rotation errors
    #[error("rotation failed for key {0}: {1}")]
    RotationFailed(String, String),

    // Shamir errors
    #[error("shamir secret sharing error: {0}")]
    ShamirInvalid(String),

    // I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("deserialization error: {0}")]
    Deserialization(String),

    // CBOR errors
    #[error("CBOR encoding error: {0}")]
    CborEncode(String),
    #[error("CBOR decoding error: {0}")]
    CborDecode(String),
}

pub type Result<T> = std::result::Result<T, SigynError>;
