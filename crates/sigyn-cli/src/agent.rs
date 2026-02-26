//! Passphrase agent — ssh-agent style session caching for decrypted keys.
//!
//! The agent is a background daemon that listens on a Unix socket and caches
//! decrypted private key material in memory. This avoids repeated passphrase
//! prompts when running multiple sigyn commands in sequence.
//!
//! Protocol (text lines over Unix socket):
//!   → UNLOCK <fingerprint_hex>
//!   ← OK <base64-key-material>
//!   ← NEED_PASSPHRASE
//!   → PASSPHRASE <passphrase>
//!   ← OK <base64-key-material>
//!   ← ERR <message>
//!   → LOCK
//!   ← OK
//!   → STOP
//!   ← OK

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sigyn_engine::crypto::keys::KeyFingerprint;
use sigyn_engine::identity::keygen::IdentityStore;

/// Cached key entry — stores the serialized LoadedIdentity bytes.
struct CachedKey {
    /// The raw key material (signing + encryption private keys) encoded for transport.
    key_material: Vec<u8>,
    cached_at: Instant,
}

struct AgentState {
    keys: HashMap<String, CachedKey>,
    timeout: Duration,
}

impl AgentState {
    fn new(timeout: Duration) -> Self {
        Self {
            keys: HashMap::new(),
            timeout,
        }
    }

    fn get(&self, fingerprint: &str) -> Option<&[u8]> {
        self.keys.get(fingerprint).and_then(|entry| {
            if entry.cached_at.elapsed() < self.timeout {
                Some(entry.key_material.as_slice())
            } else {
                None
            }
        })
    }

    fn insert(&mut self, fingerprint: String, key_material: Vec<u8>) {
        self.keys.insert(
            fingerprint,
            CachedKey {
                key_material,
                cached_at: Instant::now(),
            },
        );
    }

    fn clear(&mut self) {
        // Zeroize all key material before dropping
        for (_, entry) in self.keys.drain() {
            let mut material = entry.key_material;
            for byte in material.iter_mut() {
                *byte = 0;
            }
        }
    }

    fn evict_expired(&mut self) {
        self.keys
            .retain(|_, entry| entry.cached_at.elapsed() < self.timeout);
    }
}

impl Drop for AgentState {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Returns the socket directory and path for the current user.
fn agent_socket_dir() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/sigyn-agent-{}", uid))
}

fn agent_socket_path() -> PathBuf {
    agent_socket_dir().join("agent.sock")
}

/// Get the socket path from environment or default location.
pub fn get_agent_socket() -> Option<PathBuf> {
    if let Ok(sock) = std::env::var("SIGYN_AGENT_SOCK") {
        let p = PathBuf::from(sock);
        if p.exists() {
            return Some(p);
        }
    }
    let default = agent_socket_path();
    if default.exists() {
        Some(default)
    } else {
        None
    }
}

/// Try to load identity via agent. Returns the base64-encoded key material if cached.
pub fn try_agent_unlock(fingerprint: &str) -> Option<Vec<u8>> {
    let sock_path = get_agent_socket()?;
    let mut stream = UnixStream::connect(&sock_path).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;

    writeln!(stream, "UNLOCK {}", fingerprint).ok()?;
    stream.flush().ok()?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let line = line.trim();

    if let Some(b64) = line.strip_prefix("OK ") {
        base64_decode(b64).ok()
    } else {
        None
    }
}

/// Send passphrase to agent for a specific fingerprint.
#[allow(dead_code)]
pub fn agent_passphrase(fingerprint: &str, passphrase: &str) -> Result<Vec<u8>> {
    let sock_path = get_agent_socket().ok_or_else(|| anyhow::anyhow!("agent socket not found"))?;
    let mut stream =
        UnixStream::connect(&sock_path).context("failed to connect to agent socket")?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    // First try UNLOCK
    writeln!(stream, "UNLOCK {}", fingerprint)?;
    stream.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let trimmed = line.trim();

    if let Some(b64) = trimmed.strip_prefix("OK ") {
        return base64_decode(b64);
    }

    if trimmed == "NEED_PASSPHRASE" {
        // Send passphrase
        let stream_ref = reader.get_mut();
        writeln!(stream_ref, "PASSPHRASE {} {}", fingerprint, passphrase)?;
        stream_ref.flush()?;

        let mut response = String::new();
        reader.read_line(&mut response)?;
        let response = response.trim();

        if let Some(b64) = response.strip_prefix("OK ") {
            return base64_decode(b64);
        } else if let Some(err) = response.strip_prefix("ERR ") {
            anyhow::bail!("agent: {}", err);
        }
    }

    anyhow::bail!("unexpected agent response: {}", trimmed);
}

/// Cache a loaded identity's key material in the agent.
pub fn agent_cache(fingerprint: &str, key_material: &[u8]) -> Result<()> {
    let sock_path = get_agent_socket().ok_or_else(|| anyhow::anyhow!("agent socket not found"))?;
    let mut stream =
        UnixStream::connect(&sock_path).context("failed to connect to agent socket")?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let b64 = base64_encode(key_material);
    writeln!(stream, "CACHE {} {}", fingerprint, b64)?;
    stream.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    if line.trim() == "OK" {
        Ok(())
    } else {
        anyhow::bail!("agent cache failed: {}", line.trim());
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("base64 decode failed")
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Handle a single client connection.
fn handle_client(stream: UnixStream, state: Arc<Mutex<AgentState>>, home: PathBuf) {
    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }

        let trimmed = line.trim().to_string();
        let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();

        match parts.first().map(|s| s.to_uppercase()).as_deref() {
            Some("UNLOCK") => {
                let fp = parts.get(1).unwrap_or(&"");
                let mut st = state.lock().unwrap();
                st.evict_expired();
                if let Some(material) = st.get(fp) {
                    let b64 = base64_encode(material);
                    let _ = writeln!(writer, "OK {}", b64);
                } else {
                    let _ = writeln!(writer, "NEED_PASSPHRASE");
                }
            }
            Some("PASSPHRASE") => {
                let fp = parts.get(1).unwrap_or(&"").to_string();
                let passphrase = parts.get(2).unwrap_or(&"").to_string();

                let store = IdentityStore::new(home.clone());
                match KeyFingerprint::from_hex(&fp) {
                    Ok(fp_parsed) => match store.load(&fp_parsed, &passphrase) {
                        Ok(loaded) => {
                            // Serialize key material: signing_key || encryption_key
                            let signing_bytes = loaded.signing_key().to_bytes();
                            let encryption_bytes = loaded.encryption_key().to_bytes();
                            let mut material =
                                Vec::with_capacity(signing_bytes.len() + encryption_bytes.len());
                            material.extend_from_slice(&signing_bytes);
                            material.extend_from_slice(&encryption_bytes);

                            let b64 = base64_encode(&material);
                            state.lock().unwrap().insert(fp.clone(), material);
                            let _ = writeln!(writer, "OK {}", b64);
                        }
                        Err(e) => {
                            let _ = writeln!(writer, "ERR {}", e);
                        }
                    },
                    Err(e) => {
                        let _ = writeln!(writer, "ERR invalid fingerprint: {}", e);
                    }
                }
            }
            Some("CACHE") => {
                let fp = parts.get(1).unwrap_or(&"").to_string();
                let b64 = parts.get(2).unwrap_or(&"");
                match base64_decode(b64) {
                    Ok(material) => {
                        state.lock().unwrap().insert(fp, material);
                        let _ = writeln!(writer, "OK");
                    }
                    Err(_) => {
                        let _ = writeln!(writer, "ERR invalid base64");
                    }
                }
            }
            Some("LOCK") => {
                state.lock().unwrap().clear();
                let _ = writeln!(writer, "OK");
            }
            Some("STOP") => {
                state.lock().unwrap().clear();
                let _ = writeln!(writer, "OK");
                let _ = writer.flush();
                // Exit the daemon
                std::process::exit(0);
            }
            Some("STATUS") => {
                let st = state.lock().unwrap();
                let _ = writeln!(
                    writer,
                    "OK keys={} timeout={}s",
                    st.keys.len(),
                    st.timeout.as_secs()
                );
            }
            _ => {
                let _ = writeln!(writer, "ERR unknown command");
            }
        }
        let _ = writer.flush();
    }
}

/// Start the agent daemon (foreground — will be daemonized by the caller).
pub fn start_daemon(timeout_secs: u64) -> Result<()> {
    let sock_dir = agent_socket_dir();
    let sock_path = agent_socket_path();

    // Create socket directory with restricted permissions
    std::fs::create_dir_all(&sock_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    // Remove stale socket
    if sock_path.exists() {
        std::fs::remove_file(&sock_path)?;
    }

    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("failed to bind agent socket at {}", sock_path.display()))?;

    // Set socket permissions to owner-only
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;
    }

    let state = Arc::new(Mutex::new(AgentState::new(Duration::from_secs(
        timeout_secs,
    ))));

    let home = crate::config::sigyn_home();

    // Install signal handlers for clean shutdown
    let state_clone = Arc::clone(&state);
    ctrlc_handler(state_clone, sock_path.clone());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                let home = home.clone();
                std::thread::spawn(move || {
                    handle_client(stream, state, home);
                });
            }
            Err(e) => {
                eprintln!("agent: connection error: {}", e);
            }
        }
    }

    Ok(())
}

fn ctrlc_handler(state: Arc<Mutex<AgentState>>, sock_path: PathBuf) {
    let _ = std::thread::spawn(move || {
        // Use a simple approach: register SIGTERM/SIGINT handler
        // For simplicity, we use the ctrlc-like approach with signal handling
        unsafe {
            libc::signal(
                libc::SIGTERM,
                signal_handler as *const () as libc::sighandler_t,
            );
            libc::signal(
                libc::SIGINT,
                signal_handler as *const () as libc::sighandler_t,
            );
        }
    });

    // Store cleanup info in a static for the signal handler
    // (simplified approach — in production you'd use a proper signal crate)
    std::thread::spawn(move || {
        // Wait for signal via a simple polling approach
        loop {
            std::thread::sleep(Duration::from_millis(500));
            if SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::Relaxed) {
                state.lock().unwrap().clear();
                let _ = std::fs::remove_file(&sock_path);
                std::process::exit(0);
            }
        }
    });
}

static SHUTDOWN_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

extern "C" fn signal_handler(_: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Send a command to the agent and get a response.
fn send_command(command: &str) -> Result<String> {
    let sock_path = get_agent_socket().ok_or_else(|| anyhow::anyhow!("no running agent found"))?;
    let mut stream = UnixStream::connect(&sock_path).context("failed to connect to agent")?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    writeln!(stream, "{}", command)?;
    stream.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// CLI handler for `sigyn agent` subcommands.
pub fn handle_stop() -> Result<()> {
    let response = send_command("STOP")?;
    if response == "OK" {
        println!("Agent stopped.");
    } else {
        anyhow::bail!("unexpected response: {}", response);
    }
    Ok(())
}

pub fn handle_lock() -> Result<()> {
    let response = send_command("LOCK")?;
    if response == "OK" {
        println!("Agent keys cleared.");
    } else {
        anyhow::bail!("unexpected response: {}", response);
    }
    Ok(())
}

pub fn handle_status(json: bool) -> Result<()> {
    match get_agent_socket() {
        Some(sock_path) => {
            let response = send_command("STATUS")?;
            if json {
                crate::output::print_json(&serde_json::json!({
                    "running": true,
                    "socket": sock_path.display().to_string(),
                    "status": response,
                }))?;
            } else {
                println!("Agent running at {}", sock_path.display());
                println!("  {}", response.strip_prefix("OK ").unwrap_or(&response));
            }
        }
        None => {
            if json {
                crate::output::print_json(&serde_json::json!({
                    "running": false,
                }))?;
            } else {
                println!("No agent running.");
                println!("  Start one with: eval $(sigyn agent start)");
            }
        }
    }
    Ok(())
}

/// Start the agent, either forking to background or printing eval-able output.
pub fn handle_start(timeout_secs: u64, json: bool) -> Result<()> {
    let sock_path = agent_socket_path();

    // Check if already running
    if sock_path.exists() {
        if UnixStream::connect(&sock_path).is_ok() {
            if json {
                crate::output::print_json(&serde_json::json!({
                    "status": "already_running",
                    "socket": sock_path.display().to_string(),
                }))?;
            } else {
                eprintln!("Agent already running at {}", sock_path.display());
                println!(
                    "SIGYN_AGENT_SOCK={}; export SIGYN_AGENT_SOCK;",
                    sock_path.display()
                );
            }
            return Ok(());
        }
        // Stale socket — remove it
        let _ = std::fs::remove_file(&sock_path);
    }

    // Fork to background
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            anyhow::bail!("failed to fork agent daemon");
        }
        if pid > 0 {
            // Parent: print export statement
            if json {
                crate::output::print_json(&serde_json::json!({
                    "status": "started",
                    "pid": pid,
                    "socket": sock_path.display().to_string(),
                    "timeout_secs": timeout_secs,
                }))?;
            } else {
                println!(
                    "SIGYN_AGENT_SOCK={}; export SIGYN_AGENT_SOCK;",
                    sock_path.display()
                );
                eprintln!(
                    "Agent started (pid {}, timeout {}m).",
                    pid,
                    timeout_secs / 60
                );
            }
            return Ok(());
        }

        // Child: become session leader and run daemon
        libc::setsid();

        // Close stdin
        libc::close(0);

        // Redirect stdout/stderr to /dev/null
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }

    start_daemon(timeout_secs)?;
    Ok(())
}
