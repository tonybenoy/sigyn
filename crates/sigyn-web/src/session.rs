use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use sigyn_engine::crypto::envelope::EnvelopeHeader;
use sigyn_engine::crypto::keys::KeyFingerprint;
use sigyn_engine::crypto::vault_cipher::VaultCipher;
use sigyn_engine::identity::keygen::LoadedIdentity;
use sigyn_engine::policy::storage::VaultPolicy;
use sigyn_engine::vault::VaultManifest;

/// Cached vault context — holds the decrypted ciphers and metadata for a
/// vault that the user has unlocked in this session.
pub struct CachedVaultContext {
    pub vault_cipher: VaultCipher,
    pub env_ciphers: BTreeMap<String, VaultCipher>,
    pub manifest: VaultManifest,
    pub policy: VaultPolicy,
    pub header: EnvelopeHeader,
}

/// Per-user session data. Created on successful login, destroyed on logout or
/// TTL expiry. The loaded_identity holds the private signing/encryption keys
/// in memory — the passphrase is never stored.
pub struct SessionData {
    pub loaded_identity: LoadedIdentity,
    pub fingerprint: KeyFingerprint,
    pub identity_name: String,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub vault_contexts: HashMap<String, CachedVaultContext>,
}

/// Thread-safe session store with TTL-based expiry.
pub struct SessionStore {
    sessions: RwLock<HashMap<String, SessionData>>,
    timeout: Duration,
    /// Track failed login attempts per fingerprint for rate limiting.
    login_attempts: RwLock<HashMap<String, Vec<Instant>>>,
}

impl SessionStore {
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            timeout,
            login_attempts: RwLock::new(HashMap::new()),
        }
    }

    /// Generate a cryptographically random 256-bit session token.
    fn generate_token() -> String {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        hex::encode(bytes)
    }

    /// Create a new session for an authenticated identity. Returns the session token.
    pub fn create(
        &self,
        loaded_identity: LoadedIdentity,
        fingerprint: KeyFingerprint,
        identity_name: String,
    ) -> String {
        let token = Self::generate_token();
        let now = Instant::now();
        let data = SessionData {
            loaded_identity,
            fingerprint,
            identity_name,
            created_at: now,
            last_activity: now,
            vault_contexts: HashMap::new(),
        };
        self.sessions
            .write()
            .expect("session lock poisoned")
            .insert(token.clone(), data);
        token
    }

    /// Look up a session by token, updating last_activity if found.
    /// Returns None if the session doesn't exist or has expired.
    pub fn get_and_touch(&self, token: &str) -> bool {
        let mut sessions = self.sessions.write().expect("session lock poisoned");
        if let Some(session) = sessions.get_mut(token) {
            if session.last_activity.elapsed() > self.timeout {
                sessions.remove(token);
                return false;
            }
            session.last_activity = Instant::now();
            true
        } else {
            false
        }
    }

    /// Execute a closure with read access to the session data.
    pub fn with_session<F, R>(&self, token: &str, f: F) -> Option<R>
    where
        F: FnOnce(&SessionData) -> R,
    {
        let sessions = self.sessions.read().expect("session lock poisoned");
        sessions.get(token).map(f)
    }

    /// Execute a closure with mutable access to the session data.
    pub fn with_session_mut<F, R>(&self, token: &str, f: F) -> Option<R>
    where
        F: FnOnce(&mut SessionData) -> R,
    {
        let mut sessions = self.sessions.write().expect("session lock poisoned");
        sessions.get_mut(token).map(f)
    }

    /// Destroy a session (logout).
    pub fn destroy(&self, token: &str) {
        self.sessions
            .write()
            .expect("session lock poisoned")
            .remove(token);
    }

    /// Sweep expired sessions. Called periodically by a background task.
    pub fn sweep_expired(&self) {
        let mut sessions = self.sessions.write().expect("session lock poisoned");
        sessions.retain(|_, data| data.last_activity.elapsed() <= self.timeout);
    }

    /// Check if a fingerprint has exceeded the login rate limit.
    /// Returns true if rate-limited.
    pub fn is_rate_limited(&self, fingerprint_hex: &str) -> bool {
        let attempts = self
            .login_attempts
            .read()
            .expect("rate limit lock poisoned");
        if let Some(times) = attempts.get(fingerprint_hex) {
            let recent = times
                .iter()
                .filter(|t| t.elapsed() < Duration::from_secs(60))
                .count();
            recent >= 5
        } else {
            false
        }
    }

    /// Record a failed login attempt.
    pub fn record_failed_login(&self, fingerprint_hex: &str) {
        let mut attempts = self
            .login_attempts
            .write()
            .expect("rate limit lock poisoned");
        let times = attempts.entry(fingerprint_hex.to_string()).or_default();
        times.retain(|t| t.elapsed() < Duration::from_secs(60));
        times.push(Instant::now());
    }

    /// Clear rate limit tracking for a fingerprint (on successful login).
    pub fn clear_rate_limit(&self, fingerprint_hex: &str) {
        let mut attempts = self
            .login_attempts
            .write()
            .expect("rate limit lock poisoned");
        attempts.remove(fingerprint_hex);
    }
}
